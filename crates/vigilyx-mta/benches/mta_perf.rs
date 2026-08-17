use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::runtime::{Builder, Runtime};
use vigilyx_core::models::{EmailSession, Protocol};
use vigilyx_core::security::ThreatLevel;
use vigilyx_mta::config::{DownstreamConfig, MtaConfig, is_trusted_upstream_ip};
use vigilyx_mta::dlp::{detect_direction, run_dlp_scan};
use vigilyx_mta::server::connection::{HandleResult, SmtpConnection};

fn test_config() -> Arc<MtaConfig> {
    Arc::new(MtaConfig {
        listen_smtp: "127.0.0.1:2525".parse().expect("valid listen addr"),
        listen_submission: None,
        listen_smtps: None,
        max_connections: 10,
        tls: None,
        downstream: DownstreamConfig {
            host: "127.0.0.1".into(),
            port: 25,
            starttls: false,
            timeout_secs: 5,
        },
        outbound: None,
        local_domains: vec!["test.com".into(), "corp.com".into()],
        trusted_upstream_cidrs: Vec::new(),
        inline_timeout_secs: 8,
        fail_open: true,
        require_starttls: false,
        quarantine_threshold: ThreatLevel::Medium,
        reject_threshold: ThreatLevel::Critical,
        max_message_size: 1024 * 1024,
        max_recipients: 10,
        database_url: String::new(),
        redis_url: None,
        hostname: "bench-mta".into(),
        dlp: vigilyx_mta::dlp::DlpConfig::default(),
    })
}

fn run_handle_once(rt: &Runtime, config: &Arc<MtaConfig>, input: &[u8]) -> usize {
    rt.block_on(async {
        // Size the in-memory transport to the payload under test; otherwise large
        // benchmark messages deadlock while write_all waits for a reader.
        let (mut client_stream, server_stream) =
            tokio::io::duplex(input.len().max(16 * 1024) + 1024);
        client_stream
            .write_all(input)
            .await
            .expect("write bench input");
        client_stream.shutdown().await.expect("shutdown writer");

        let mut server_stream = BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            Arc::clone(config),
            false,
        );

        let results = conn.handle(&mut server_stream, false).await;
        results
            .iter()
            .filter(|result| matches!(result, HandleResult::Email(_, _)))
            .count()
    })
}

fn run_handle_concurrent(
    rt: &Runtime,
    config: &Arc<MtaConfig>,
    input: &[u8],
    concurrency: usize,
) -> usize {
    rt.block_on(async {
        let shared_input: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        let mut handles = Vec::with_capacity(concurrency);

        for idx in 0..concurrency {
            let input = Arc::clone(&shared_input);
            let config = Arc::clone(config);
            handles.push(tokio::spawn(async move {
                let (mut client_stream, server_stream) =
                    tokio::io::duplex(input.len().max(16 * 1024) + 1024);
                client_stream
                    .write_all(input.as_ref())
                    .await
                    .expect("write concurrent bench input");
                client_stream.shutdown().await.expect("shutdown writer");

                let mut server_stream = BufStream::new(server_stream);
                let mut conn = SmtpConnection::new(
                    format!("127.0.0.{}", (idx % 250) + 1),
                    10000 + idx as u16,
                    "0.0.0.0".into(),
                    25,
                    config,
                    false,
                );

                let results = conn.handle(&mut server_stream, false).await;
                results
                    .iter()
                    .filter(|result| matches!(result, HandleResult::Email(_, _)))
                    .count()
            }));
        }

        let mut total = 0usize;
        for handle in handles {
            total += handle
                .await
                .expect("concurrent bench task should not panic");
        }
        total
    })
}

fn message_body(target_len: usize) -> String {
    let line = "Body text for benchmark line 0123456789\r\n";
    let repeats = (target_len / line.len()).max(1);
    line.repeat(repeats)
}

fn build_data_input(body_len: usize) -> Vec<u8> {
    let body = message_body(body_len);
    format!(
        concat!(
            "EHLO client.test\r\n",
            "MAIL FROM:<sender@test.com>\r\n",
            "RCPT TO:<rcpt@test.com>\r\n",
            "DATA\r\n",
            "From: sender@test.com\r\n",
            "To: rcpt@test.com\r\n",
            "Subject: DATA Bench\r\n",
            "Message-ID: <bench-data@test.com>\r\n",
            "\r\n",
            "{body}",
            ".\r\n"
        ),
        body = body,
    )
    .into_bytes()
}

fn build_bdat_input(body_len: usize) -> Vec<u8> {
    let body = message_body(body_len);
    let bdat_body = format!(
        concat!(
            "From: sender@test.com\r\n",
            "To: rcpt@test.com\r\n",
            "Subject: BDAT Bench\r\n",
            "Message-ID: <bench-bdat@test.com>\r\n",
            "\r\n",
            "{body}"
        ),
        body = body,
    )
    .into_bytes();

    [
        format!(
            concat!(
                "EHLO client.test\r\n",
                "MAIL FROM:<sender@test.com>\r\n",
                "RCPT TO:<rcpt@test.com>\r\n",
                "BDAT {} LAST\r\n"
            ),
            bdat_body.len()
        )
        .into_bytes(),
        bdat_body,
    ]
    .concat()
}

fn bench_detect_direction(c: &mut Criterion) {
    let local_domains = vec!["corp.com".to_string(), "internal.example".to_string()];
    let outbound_rcpts = vec!["user@corp.com".to_string(), "ext@gmail.com".to_string()];
    let inbound_rcpts = vec!["user@corp.com".to_string()];

    let mut group = c.benchmark_group("mta_direction");
    group.sample_size(50);
    group.bench_function("outbound_mixed_rcpts", |b| {
        b.iter(|| {
            black_box(detect_direction(
                Some("alice@corp.com"),
                black_box(&outbound_rcpts),
                black_box(&local_domains),
                true,
            ))
        })
    });
    group.bench_function("inbound_spoof_blocked", |b| {
        b.iter(|| {
            black_box(detect_direction(
                Some("ceo@corp.com"),
                black_box(&inbound_rcpts),
                black_box(&local_domains),
                false,
            ))
        })
    });
    group.finish();
}

fn bench_trusted_upstream_lookup(c: &mut Criterion) {
    let cidrs = (0..128)
        .map(|i| format!("10.{}.0.0/16", i))
        .collect::<Vec<_>>();

    let mut group = c.benchmark_group("mta_trusted_upstream");
    group.sample_size(50);
    group.bench_function("128_cidrs_hit", |b| {
        b.iter(|| black_box(is_trusted_upstream_ip("10.42.18.9", black_box(&cidrs))))
    });
    group.bench_function("128_cidrs_miss", |b| {
        b.iter(|| black_box(is_trusted_upstream_ip("203.0.113.42", black_box(&cidrs))))
    });
    group.finish();
}

fn bench_dlp_scan(c: &mut Criterion) {
    let mut clean_session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".into(),
        25000,
        "10.0.0.2".into(),
        25,
    );
    clean_session.subject = Some("Quarterly review".into());
    clean_session.content.body_text = Some("normal body ".repeat(2048));

    let mut hit_session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".into(),
        25000,
        "10.0.0.2".into(),
        25,
    );
    hit_session.subject = Some("Payment details".into());
    hit_session.content.body_text = Some(format!(
        "{}\n{}",
        "normal body ".repeat(1024),
        "请将款项转到以下卡号：4532015112830366，谢谢。".repeat(128)
    ));

    let mut group = c.benchmark_group("mta_dlp");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));
    group.bench_function("clean_body_16kb", |b| {
        b.iter(|| black_box(run_dlp_scan(black_box(&clean_session))))
    });
    group.bench_function("hit_body_16kb", |b| {
        b.iter(|| black_box(run_dlp_scan(black_box(&hit_session))))
    });
    group.finish();
}

fn bench_smtp_handle(c: &mut Criterion) {
    let config = test_config();
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let data_small_input = build_data_input(128);
    let data_large_input = build_data_input(256 * 1024);
    let bdat_small_input = build_bdat_input(128);
    let bdat_large_input = build_bdat_input(256 * 1024);

    assert_eq!(run_handle_once(&rt, &config, &data_small_input), 1);
    assert_eq!(run_handle_once(&rt, &config, &data_large_input), 1);
    assert_eq!(run_handle_once(&rt, &config, &bdat_small_input), 1);
    assert_eq!(run_handle_once(&rt, &config, &bdat_large_input), 1);

    let mut group = c.benchmark_group("mta_handle");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(6));
    group.throughput(Throughput::Bytes(data_small_input.len() as u64));
    group.bench_function("data_single_message_small", |b| {
        b.iter_batched(
            || data_small_input.clone(),
            |input| black_box(run_handle_once(&rt, &config, &input)),
            BatchSize::SmallInput,
        )
    });
    group.throughput(Throughput::Bytes(data_large_input.len() as u64));
    group.bench_function("data_single_message_256k", |b| {
        b.iter_batched(
            || data_large_input.clone(),
            |input| black_box(run_handle_once(&rt, &config, &input)),
            BatchSize::SmallInput,
        )
    });
    group.throughput(Throughput::Bytes(bdat_small_input.len() as u64));
    group.bench_function("bdat_single_message_small", |b| {
        b.iter_batched(
            || bdat_small_input.clone(),
            |input| black_box(run_handle_once(&rt, &config, &input)),
            BatchSize::SmallInput,
        )
    });
    group.throughput(Throughput::Bytes(bdat_large_input.len() as u64));
    group.bench_function("bdat_single_message_256k", |b| {
        b.iter_batched(
            || bdat_large_input.clone(),
            |input| black_box(run_handle_once(&rt, &config, &input)),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_smtp_handle_concurrent(c: &mut Criterion) {
    let config = test_config();
    let rt = Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio multi-thread runtime");
    let data_small_input = build_data_input(128);
    let data_large_input = build_data_input(256 * 1024);

    assert_eq!(
        run_handle_concurrent(&rt, &config, &data_small_input, 32),
        32
    );
    assert_eq!(run_handle_concurrent(&rt, &config, &data_large_input, 8), 8);

    let mut group = c.benchmark_group("mta_handle_concurrent");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(32));
    group.bench_function("data_32x_small", |b| {
        b.iter_batched(
            || data_small_input.clone(),
            |input| black_box(run_handle_concurrent(&rt, &config, &input, 32)),
            BatchSize::SmallInput,
        )
    });
    group.throughput(Throughput::Elements(8));
    group.bench_function("data_8x_256k", |b| {
        b.iter_batched(
            || data_large_input.clone(),
            |input| black_box(run_handle_concurrent(&rt, &config, &input, 8)),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_detect_direction,
    bench_trusted_upstream_lookup,
    bench_dlp_scan,
    bench_smtp_handle,
    bench_smtp_handle_concurrent
);
criterion_main!(benches);
