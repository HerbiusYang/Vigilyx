#![cfg(feature = "infra-tests")]

use anyhow::{Context, Result, ensure};
use redis::aio::MultiplexedConnection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vigilyx_db::mq::{MqClient, MqConfig, StreamClient};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestMessage {
    sequence: u32,
    payload: String,
}

fn test_redis_url() -> Result<String> {
    let url = std::env::var("VIGILYX_TEST_REDIS_URL")
        .context("VIGILYX_TEST_REDIS_URL must point to a disposable Valkey instance")?;
    ensure!(
        std::env::var("VIGILYX_ALLOW_REAL_INFRA_TESTS").as_deref() == Ok("1"),
        "set VIGILYX_ALLOW_REAL_INFRA_TESTS=1 to acknowledge destructive cleanup of random test keys"
    );
    Ok(url)
}

async fn admin_connection(url: &str) -> Result<MultiplexedConnection> {
    let client = redis::Client::open(url)?;
    Ok(client.get_multiplexed_async_connection().await?)
}

async fn delete_test_keys(conn: &mut MultiplexedConnection, keys: &[&str]) -> Result<()> {
    let _: u64 = redis::cmd("DEL").arg(keys).query_async(conn).await?;
    Ok(())
}

#[tokio::test]
async fn real_stream_covers_pel_autoclaim_ack_dlq_and_reconnect() -> Result<()> {
    let url = test_redis_url()?;
    let suffix = Uuid::new_v4().simple().to_string();
    let stream = format!("vigilyx:test:{suffix}:sessions");
    let dlq = format!("vigilyx:test:{suffix}:sessions:dlq");
    let group = format!("vigilyx-test-{suffix}");

    let config = MqConfig {
        redis_url: url.clone(),
        stream_max_len: 100,
        batch_size: 10,
        reconnect_interval_secs: 0,
        max_retries: 2,
        ..MqConfig::default()
    };
    let mq = MqClient::new(config);
    mq.connect().await?;

    let consumer_a = StreamClient::new(mq.clone(), &group, "consumer-a");
    let consumer_b = StreamClient::new(mq.clone(), &group, "consumer-b");
    consumer_a.ensure_group(&stream).await?;
    consumer_a.ensure_group(&stream).await?;

    let messages = vec![
        TestMessage {
            sequence: 1,
            payload: "first".to_string(),
        },
        TestMessage {
            sequence: 2,
            payload: "second".to_string(),
        },
    ];
    assert_eq!(consumer_a.xadd_batch(&stream, &messages).await?, 2);

    let delivered = consumer_a
        .xreadgroup::<TestMessage>(&stream, 10, Some(100))
        .await?;
    assert_eq!(delivered.len(), 2);
    assert_eq!(delivered[0].1, messages[0]);
    assert_eq!(consumer_a.xpending_summary(&stream).await?.total, 2);

    // A second consumer represents a replacement process after consumer A died.
    // min_idle=0 makes ownership transfer deterministic without sleeping.
    let claimed = consumer_b.xautoclaim::<TestMessage>(&stream, 0, 10).await?;
    assert_eq!(claimed.len(), 2);
    assert_eq!(claimed[1].1, messages[1]);

    let poison_id = &claimed[0].0;
    consumer_b
        .xadd_dlq(
            &dlq,
            poison_id,
            &claimed[0].1,
            "synthetic processing failure",
        )
        .await?;
    assert_eq!(consumer_b.xlen(&dlq).await?, 1);

    let claimed_ids: Vec<&str> = claimed.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(consumer_b.xack(&stream, &claimed_ids).await?, 2);
    assert_eq!(consumer_b.xpending_summary(&stream).await?.total, 0);

    // Kill the client's normal connections from a separate administrative
    // connection. ConnectionManager must recreate its socket on the next write.
    let mut admin = admin_connection(&url).await?;
    let _: i64 = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("NORMAL")
        .arg("SKIPME")
        .arg("YES")
        .query_async(&mut admin)
        .await?;

    let after_disconnect = TestMessage {
        sequence: 3,
        payload: "after reconnect".to_string(),
    };
    consumer_b.xadd_one(&stream, &after_disconnect).await?;

    // The dedicated blocking read socket may report the killed connection once;
    // the implementation resets it and the following read must establish a new one.
    let reconnected = match consumer_b
        .xreadgroup::<TestMessage>(&stream, 1, Some(100))
        .await
    {
        Ok(messages) => messages,
        Err(_) => {
            consumer_b
                .xreadgroup::<TestMessage>(&stream, 1, Some(100))
                .await?
        }
    };
    assert_eq!(reconnected.len(), 1);
    assert_eq!(reconnected[0].1, after_disconnect);
    assert_eq!(consumer_b.xack(&stream, &[&reconnected[0].0]).await?, 1);

    let mut cleanup = admin_connection(&url).await?;
    delete_test_keys(&mut cleanup, &[&stream, &dlq]).await?;
    Ok(())
}
