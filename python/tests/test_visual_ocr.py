"""Focused tests for bounded visual OCR input and coverage semantics."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from vigilyx_ai.visual_ocr import VisualOcrResult, decode_image_base64, _parse_tsv


def test_decode_image_payload_requires_allowed_type_and_size():
    assert decode_image_base64("aGVsbG8=", "image/png") == b"hello"
    assert decode_image_base64("aGVsbG8=", "text/html") is None
    assert decode_image_base64("not-base64", "image/png") is None


def test_parse_tsv_returns_text_and_mean_confidence():
    tsv = "level\tconf\ttext\n5\t80.0\t账\n5\t60.0\t户"
    text, confidence = _parse_tsv(tsv)
    assert text == "账 户"
    assert confidence == 0.7


def test_visual_endpoint_keeps_ocr_as_coverage_observation():
    from vigilyx_ai import api

    fake = VisualOcrResult("html_image_1", "ok", "账户异常", 0.91)
    with patch.object(api, "_INTERNAL_TOKEN", "test-secret-token"), \
         patch.object(api, "run_image_ocr", return_value=fake):
        with TestClient(api.app) as client:
            response = client.post(
                "/analyze/visual",
                headers={"X-Internal-Token": "test-secret-token"},
                json={
                    "session_id": "s1",
                    "images": [
                        {
                            "source_id": "html_image_1",
                            "media_type": "image/png",
                            "content_base64": "aGVsbG8=",
                        }
                    ],
                },
            )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "coverage_limited": False,
        "results": [
            {
                "source_id": "html_image_1",
                "status": "ok",
                "text": "账户异常",
                "confidence": 0.91,
                "reason": None,
            }
        ],
    }


def test_visual_endpoint_rejects_external_or_unsupported_image_payload():
    from vigilyx_ai import api

    with patch.object(api, "_INTERNAL_TOKEN", "test-secret-token"):
        with TestClient(api.app) as client:
            response = client.post(
                "/analyze/visual",
                headers={"X-Internal-Token": "test-secret-token"},
                json={
                    "session_id": "s1",
                    "images": [
                        {
                            "source_id": "external_1",
                            "media_type": "text/html",
                            "content_base64": "aGVsbG8=",
                        }
                    ],
                },
            )

    assert response.status_code == 200
    assert response.json()["coverage_limited"] is True
    assert response.json()["results"][0]["status"] == "rejected"

