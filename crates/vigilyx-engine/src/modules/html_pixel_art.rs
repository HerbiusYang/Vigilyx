//! HTML pixel art detection module.
//!
//! Detects HTML table-rendered QR codes and CSS div-based pixel art.
//! Attackers use `<table>` cells with `bgcolor` to render binary QR codes,
//! and `<div>` elements with float/margin-left/background-color to draw pixel text,
//! bypassing image-based detection (OCR, sandbox analysis).
//!
//! Three-stage pipeline:
//! - Stage 1: String pre-filter (skips 99%+ normal emails quickly)
//! - Stage 2: DOM parsing + structural analysis
//! - Stage 3: rqrr QR decode + URL extraction

use std::collections::HashSet;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use scraper::{Html, Selector};

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

/// Maximum number of tables to analyze (prevents timeout on large HTML)
const MAX_TABLES_TO_ANALYZE: usize = 10;
/// Minimum QR code grid size (Version 1 = 21x21)
const MIN_QR_GRID: usize = 21;
/// Pre-filter threshold: minimum bgcolor occurrence count
const PREFILTER_BGCOLOR_THRESHOLD: usize = 200;
/// Pre-filter threshold: minimum <td occurrence count
const PREFILTER_TD_THRESHOLD: usize = 400;
/// Pre-filter threshold: minimum float/margin-left occurrence count
const PREFILTER_PIXEL_ART_THRESHOLD: usize = 50;

pub struct HtmlPixelArtModule {
    meta: ModuleMetadata,
}

impl Default for HtmlPixelArtModule {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlPixelArtModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "html_pixel_art".to_string(),
                name: "HTML Pixel Art Detection".to_string(),
                description: "Detects HTML table-rendered QR codes and CSS div-based pixel art text"
                    .to_string(),
                pillar: Pillar::Content,
                depends_on: vec![],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }
}

#[async_trait]
impl SecurityModule for HtmlPixelArtModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        let body_html = match ctx.session.content.body_html.as_deref() {
            Some(h) if !h.is_empty() => h,
            _ => {
                return Ok(ModuleResult {
                    module_id: self.meta.id.clone(),
                    module_name: self.meta.name.clone(),
                    pillar: self.meta.pillar,
                    threat_level: ThreatLevel::Safe,
                    confidence: 1.0,
                    categories: vec![],
                    summary: "Email has no HTML body".to_string(),
                    evidence: vec![],
                    details: serde_json::json!({}),
                    duration_ms: start.elapsed().as_millis() as u64,
                    analyzed_at: Utc::now(),
                    bpa: None,
                    engine_id: None,
                });
            }
        };

        let html_lower = body_html.to_lowercase();
        let mut total_score = 0.0_f64;
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut details = serde_json::Map::new();

        
       // Stage 1:
        
        let bgcolor_count = html_lower.matches("bgcolor").count();
        let td_count = html_lower.matches("<td").count();
        let float_count =
            html_lower.matches("float:").count() + html_lower.matches("float :").count();
        let margin_count = html_lower.matches("margin-left:").count()
            + html_lower.matches("margin-left :").count();

        let check_qr =
            bgcolor_count >= PREFILTER_BGCOLOR_THRESHOLD && td_count >= PREFILTER_TD_THRESHOLD;
        let check_pixel_art = float_count >= PREFILTER_PIXEL_ART_THRESHOLD
            && margin_count >= PREFILTER_PIXEL_ART_THRESHOLD;

        if !check_qr && !check_pixel_art {
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 1.0,
                categories: vec![],
                summary: "No pixel art patterns found in HTML body".to_string(),
                evidence: vec![],
                details: serde_json::json!({
                    "score": 0.0,
                    "bgcolor_count": bgcolor_count,
                    "td_count": td_count,
                }),
                duration_ms: start.elapsed().as_millis() as u64,
                analyzed_at: Utc::now(),
                bpa: None,
                engine_id: None,
            });
        }

        
       // Stage 2: DOM parsing + structural analysis
        
        let document = Html::parse_document(body_html);

       // QR table detect
        if check_qr && let Ok(table_sel) = Selector::parse("table") {
            let mut qr_tables_found = 0u32;
            let mut decoded_urls: Vec<String> = Vec::new();

            for table in document.select(&table_sel).take(MAX_TABLES_TO_ANALYZE) {
                let analysis = analyze_table_for_qr(&table);
                if analysis.score >= 0.40 {
                    qr_tables_found += 1;
                    total_score += analysis.score;
                    categories.push("html_qr_code".to_string());

                    let mut desc = format!(
                        "HTML table-rendered QR code: {}x{} grid, {} colors, cells {}",
                        analysis.rows,
                        analysis.cols,
                        analysis.unique_colors,
                        if analysis.empty_cells {
                            "all empty"
                        } else {
                            "contain content"
                        },
                    );
                    if analysis.has_finder_patterns {
                        desc.push_str(", QR finder pattern confirmed");
                    }

                    evidence.push(Evidence {
                        description: desc,
                        location: Some("body_html".to_string()),
                        snippet: Some(format!(
                            "<table> {}x{} bgcolor grid",
                            analysis.rows, analysis.cols
                        )),
                    });

                   // Stage 3: QR Decode
                    if let Some(ref grid) = analysis.grid
                        && let Some(decoded) = decode_qr_from_grid(grid)
                    {
                        total_score += 0.05;
                        decoded_urls.push(decoded.clone());

                       // Check if decoded URL contains recipient email address
                        let url_lower = decoded.to_lowercase();
                        let has_recipient = ctx
                            .session
                            .rcpt_to
                            .iter()
                            .any(|r| url_lower.contains(&r.to_lowercase()));
                        if has_recipient {
                            total_score += 0.15;
                            categories.push("qr_targeted_phishing".to_string());
                        }

                        categories.push("qr_malicious_url".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "QR code decoded URL: {}{}",
                                &decoded,
                                if has_recipient {
                                    " (contains recipient email - targeted phishing)"
                                } else {
                                    ""
                                },
                            ),
                            location: Some("qr_decoded".to_string()),
                            snippet: Some(decoded),
                        });
                    }
                }
            }

            details.insert("qr_tables_found".into(), qr_tables_found.into());
            if !decoded_urls.is_empty() {
                details.insert(
                    "qr_decoded_urls".into(),
                    serde_json::Value::Array(
                        decoded_urls
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
        }

       // CSS detect
        if check_pixel_art {
            let pa = analyze_pixel_art_divs(&document);
            if pa.score > 0.0 {
                total_score += pa.score;
                categories.push("html_pixel_art".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "CSS pixel art detected: {} positioned divs, {} colors, {} text chars, element/text ratio {:.1}",
                        pa.positioned_div_count,
                        pa.unique_colors,
                        pa.text_content_length,
                        pa.element_to_text_ratio,
                    ),
                    location: Some("body_html".to_string()),
                    snippet: None,
                });
            }
            details.insert("pixel_art_divs".into(), pa.positioned_div_count.into());
        }

        total_score = total_score.min(1.0);
        categories.sort_unstable();
        categories.dedup();

        let threat_level = ThreatLevel::from_score(total_score);
        let summary = if threat_level == ThreatLevel::Safe {
            "No malicious pixel art found in HTML body".to_string()
        } else {
            let cat_str = categories.join(", ");
            format!(
                "HTML pixel art detection found {} anomalies ({})",
                evidence.len(),
                cat_str,
            )
        };

        details.insert("score".into(), total_score.into());
        details.insert("bgcolor_count".into(), bgcolor_count.into());
        details.insert("td_count".into(), td_count.into());

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.90,
            categories,
            summary,
            evidence,
            details: serde_json::Value::Object(details),
            duration_ms: start.elapsed().as_millis() as u64,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}


// QR table analysis


struct QrTableAnalysis {
    rows: usize,
    cols: usize,
    unique_colors: usize,
    empty_cells: bool,
    has_finder_patterns: bool,
    grid: Option<Vec<Vec<bool>>>,
    score: f64,
}

fn analyze_table_for_qr(table: &scraper::ElementRef) -> QrTableAnalysis {
    let tr_sel = Selector::parse("tr").expect("valid selector");
    let td_sel = Selector::parse("td").expect("valid selector");

    let mut grid: Vec<Vec<bool>> = Vec::new();
    let mut all_colors: HashSet<String> = HashSet::new();
    let mut all_empty = true;
    let mut widths: HashSet<String> = HashSet::new();

    for tr in table.select(&tr_sel) {
        let mut row: Vec<bool> = Vec::new();
        for td in tr.select(&td_sel) {
            let bgcolor = td
                .value()
                .attr("bgcolor")
                .map(|s| s.to_uppercase())
                .or_else(|| extract_bg_from_style(&td))
                .unwrap_or_else(|| "#FFFFFF".to_string());

            all_colors.insert(normalize_color(&bgcolor));

            let text: String = td.text().collect();
            let trimmed = text.trim();
            if !trimmed.is_empty() && trimmed != "\u{00a0}" && trimmed != "&nbsp;" {
                all_empty = false;
            }

            if let Some(w) = td.value().attr("width") {
                widths.insert(w.to_string());
            }

            row.push(is_dark_color(&bgcolor));
        }
        if !row.is_empty() {
            grid.push(row);
        }
    }

    let rows = grid.len();
    let cols = grid.first().map(|r| r.len()).unwrap_or(0);
    let is_square = rows >= MIN_QR_GRID
        && cols >= MIN_QR_GRID
        && (rows as i32 - cols as i32).unsigned_abs() <= 3;
    let binary_colors = all_colors.len() == 2;
    let uniform_size = widths.len() <= 2;

    let mut score = 0.0;
    if is_square {
        score += 0.20;
    }
    if binary_colors {
        score += 0.15;
    }
    if all_empty {
        score += 0.10;
    }
    if uniform_size && !widths.is_empty() {
       // Check whether cells are small (<= 8px)
        let all_small = widths.iter().all(|w| {
            w.trim_end_matches("px")
                .parse::<f64>()
                .map(|v| v <= 8.0)
                .unwrap_or(false)
        });
        if all_small {
            score += 0.05;
        }
    }

    let has_finder = is_square && binary_colors && check_finder_patterns(&grid);
    if has_finder {
        score += 0.30;
    }

    let keep_grid = score >= 0.40;

    QrTableAnalysis {
        rows,
        cols,
        unique_colors: all_colors.len(),
        empty_cells: all_empty,
        has_finder_patterns: has_finder,
        grid: if keep_grid { Some(grid) } else { None },
        score,
    }
}

/// QR finder pattern detection: checks 3 corners for 7x7 patterns
fn check_finder_patterns(grid: &[Vec<bool>]) -> bool {
    if grid.len() < 7 || grid[0].len() < 7 {
        return false;
    }
    let rows = grid.len();
    let cols = grid[0].len();

    let has_tl = check_finder_at(grid, 0, 0);
    let has_tr = check_finder_at(grid, 0, cols.saturating_sub(7));
    let has_bl = check_finder_at(grid, rows.saturating_sub(7), 0);

   // At least 2/3 corners must match (allows for partial damage)
    [has_tl, has_tr, has_bl].iter().filter(|&&x| x).count() >= 2
}

/// Check whether a 7x7 region matches the QR finder pattern
fn check_finder_at(grid: &[Vec<bool>], start_row: usize, start_col: usize) -> bool {
    #[rustfmt::skip]
    const PATTERN: [[u8; 7]; 7] = [
        [1,1,1,1,1,1,1],
        [1,0,0,0,0,0,1],
        [1,0,1,1,1,0,1],
        [1,0,1,1,1,0,1],
        [1,0,1,1,1,0,1],
        [1,0,0,0,0,0,1],
        [1,1,1,1,1,1,1],
    ];

    let mut match_count = 0u32;
    let total = 49u32;
    for (r, row) in PATTERN.iter().enumerate() {
        for (c, &expected) in row.iter().enumerate() {
            let gr = start_row + r;
            let gc = start_col + c;
            if gr < grid.len() && gc < grid[gr].len() && grid[gr][gc] == (expected == 1) {
                match_count += 1;
            }
        }
    }
    
    match_count as f64 / total as f64 > 0.85
}


// QR Decode (rqrr)


fn decode_qr_from_grid(grid: &[Vec<bool>]) -> Option<String> {
    let height = grid.len();
    let width = grid.first().map(|r| r.len()).unwrap_or(0);
    if width == 0 || height == 0 {
        return None;
    }

    let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        if y < grid.len() && x < grid[y].len() {
            if grid[y][x] { 0u8 } else { 255u8 }
        } else {
            255u8
        }
    });

    let grids = img.detect_grids();
    for g in grids {
        if let Ok((_meta, content)) = g.decode() {
            return Some(content);
        }
    }
    None
}


// CSS pixel art analysis


struct PixelArtAnalysis {
    positioned_div_count: usize,
    unique_colors: usize,
    text_content_length: usize,
    element_to_text_ratio: f64,
    score: f64,
}

fn analyze_pixel_art_divs(document: &Html) -> PixelArtAnalysis {
    let div_sel = Selector::parse("div[style]").expect("valid selector");

    let mut positioned_count = 0usize;
    let mut colors: HashSet<String> = HashSet::new();
    let mut all_small = true;

    for div in document.select(&div_sel) {
        let style = match div.value().attr("style") {
            Some(s) => s.to_lowercase(),
            None => continue,
        };

        let has_positioning = style.contains("float:") || style.contains("margin-left:");
        let has_size = style.contains("width:") && style.contains("height:");

        if has_positioning && has_size {
            positioned_count += 1;

            if let Some(bg) = extract_bg_color_from_css(&style) {
                colors.insert(bg);
            }

           // Check whether element is small
            if let Some(w) = extract_px_value(&style, "width:")
                && w > 8.0
            {
                all_small = false;
            }
            if let Some(h) = extract_px_value(&style, "height:")
                && h > 8.0
            {
                all_small = false;
            }
        }
    }

   // Measure text content length
    let body_text: String = document.root_element().text().collect();
    let text_len = body_text.chars().filter(|c| !c.is_whitespace()).count();

    let ratio = if text_len > 0 {
        positioned_count as f64 / text_len as f64
    } else if positioned_count > 0 {
        100.0
    } else {
        0.0
    };

    let mut score = 0.0;
    if positioned_count >= 100 && colors.len() <= 3 && all_small {
        score += 0.35;
    }
    if text_len < 50 && positioned_count >= 100 {
        score += 0.15;
    }
    if ratio > 5.0 && positioned_count >= 50 {
        score += 0.10;
    }

    PixelArtAnalysis {
        positioned_div_count: positioned_count,
        unique_colors: colors.len(),
        text_content_length: text_len,
        element_to_text_ratio: ratio,
        score,
    }
}


// Helper functions


/// Extract background-color from inline style attribute
fn extract_bg_from_style(el: &scraper::ElementRef) -> Option<String> {
    let style = el.value().attr("style")?;
    extract_bg_color_from_css(&style.to_lowercase())
}

/// Extract background-color value from a CSS string
fn extract_bg_color_from_css(css: &str) -> Option<String> {
   // match background-color: #xxx background: #xxx
    for prefix in &["background-color:", "background:"] {
        if let Some(pos) = css.find(prefix) {
            let rest = &css[pos + prefix.len()..];
            let val = rest.trim().split(';').next()?.split_whitespace().next()?;
            return Some(normalize_color(val));
        }
    }
    None
}

/// Normalize color to unified format: #000 -> #000000, rgb(0,0,0) -> #000000
fn normalize_color(color: &str) -> String {
    let c = color.trim().to_uppercase();
    if c.len() == 4 && c.starts_with('#') {
       // #RGB -> #RRGGBB
        let chars: Vec<char> = c.chars().collect();
        return format!(
            "#{}{}{}{}{}{}",
            chars[1], chars[1], chars[2], chars[2], chars[3], chars[3]
        );
    }
    c
}

/// Determine whether a color is dark (used for QR code binary conversion)
fn is_dark_color(color: &str) -> bool {
    let c = normalize_color(color);
    if c.starts_with('#') && c.len() == 7 {
        let r = u8::from_str_radix(&c[1..3], 16).unwrap_or(255);
        let g = u8::from_str_radix(&c[3..5], 16).unwrap_or(255);
        let b = u8::from_str_radix(&c[5..7], 16).unwrap_or(255);
        let luminance = 0.299 * r as f64 + 0.587 * g as f64 + 0.114 * b as f64;
        return luminance < 128.0;
    }
   // Named dark colors
    matches!(
        color.to_lowercase().trim(),
        "black" | "dark" | "navy" | "darkblue" | "darkgreen"
    )
}

/// Extract px value from CSS string: "width: 4px" -> 4.0
fn extract_px_value(css: &str, property: &str) -> Option<f64> {
    let pos = css.find(property)?;
    let rest = &css[pos + property.len()..];
    let val_str = rest.trim().split(';').next()?.trim().trim_end_matches("px");
    val_str.parse::<f64>().ok()
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;

   /// Build an NxN QR table HTML (with finder patterns)
    fn build_qr_table_html(size: usize) -> String {
        let mut html = String::from("<html><body><table cellpadding=\"0\" cellspacing=\"0\">\n");
        for r in 0..size {
            html.push_str("<tr>");
            for c in 0..size {
               // Check if in finder pattern region (top-left, top-right, bottom-left)
                let is_finder_region =
                    (r < 7 && (c < 7 || c >= size - 7)) || (r >= size - 7 && c < 7);

                let is_dark = if is_finder_region {
                   // Simplified finder pattern logic
                    let lc = if c >= size - 7 { c - (size - 7) } else { c };
                    let lr = r.min(6);
                    let lc = lc.min(6);
                    
                    lr == 0 || lr == 6 || lc == 0 || lc == 6
                    
                    || ((2..=4).contains(&lr) && (2..=4).contains(&lc))
                } else {
                    
                    (r + c) % 2 == 0
                };

                let color = if is_dark { "#000000" } else { "#FFFFFF" };
                html.push_str(&format!(
                    "<td bgcolor=\"{}\" width=\"4\" height=\"4\"></td>",
                    color
                ));
            }
            html.push_str("</tr>\n");
        }
        html.push_str("</table></body></html>");
        html
    }

    #[test]
    fn test_prefilter_triggers_on_qr_table() {
        let html = build_qr_table_html(25);
        let lower = html.to_lowercase();
        let bgcolor_count = lower.matches("bgcolor").count();
        let td_count = lower.matches("<td").count();
        assert!(
            bgcolor_count >= PREFILTER_BGCOLOR_THRESHOLD,
            "bgcolor count {} < {}",
            bgcolor_count,
            PREFILTER_BGCOLOR_THRESHOLD
        );
        assert!(
            td_count >= PREFILTER_TD_THRESHOLD,
            "td count {} < {}",
            td_count,
            PREFILTER_TD_THRESHOLD
        );
    }

    #[test]
    fn test_prefilter_skips_normal_html() {
        let html = "<html><body><table><tr><td>Name</td><td>Value</td></tr></table></body></html>";
        let lower = html.to_lowercase();
        let bgcolor_count = lower.matches("bgcolor").count();
        assert!(bgcolor_count < PREFILTER_BGCOLOR_THRESHOLD);
    }

    #[test]
    fn test_analyze_table_detects_qr_grid() {
        let html = build_qr_table_html(25);
        let doc = Html::parse_document(&html);
        let table_sel = Selector::parse("table").unwrap();
        let table = doc.select(&table_sel).next().unwrap();
        let analysis = analyze_table_for_qr(&table);

        assert_eq!(analysis.rows, 25);
        assert_eq!(analysis.cols, 25);
        assert_eq!(analysis.unique_colors, 2);
        assert!(analysis.empty_cells);
        assert!(
            analysis.score >= 0.40,
            "QR table score {} < 0.40",
            analysis.score
        );
    }

    #[test]
    fn test_finder_pattern_detection() {
        let html = build_qr_table_html(25);
        let doc = Html::parse_document(&html);
        let table_sel = Selector::parse("table").unwrap();
        let table = doc.select(&table_sel).next().unwrap();
        let analysis = analyze_table_for_qr(&table);

        assert!(
            analysis.has_finder_patterns,
            "Should detect finder patterns in QR table"
        );
        assert!(
            analysis.score >= 0.70,
            "Score with finder patterns should be >= 0.70, got {}",
            analysis.score
        );
    }

    #[test]
    fn test_legitimate_data_table_not_flagged() {
        let html = r#"<html><body>
        <table>
          <tr><th>Name</th><th>Email</th><th>Amount</th></tr>
          <tr><td>Alice</td><td>alice@test.com</td><td>$100</td></tr>
          <tr><td>Bob</td><td>bob@test.com</td><td>$200</td></tr>
          <tr><td>Charlie</td><td>charlie@test.com</td><td>$300</td></tr>
        </table>
        </body></html>"#;

        let doc = Html::parse_document(html);
        let table_sel = Selector::parse("table").unwrap();
        let table = doc.select(&table_sel).next().unwrap();
        let analysis = analyze_table_for_qr(&table);

        assert!(
            analysis.score < 0.15,
            "Legitimate table should have low score, got {}",
            analysis.score
        );
    }

    #[test]
    fn test_color_normalization() {
        assert_eq!(normalize_color("#000"), "#000000");
        assert_eq!(normalize_color("#fff"), "#FFFFFF");
        assert_eq!(normalize_color("#FF0000"), "#FF0000");
        assert_eq!(normalize_color("#abc"), "#AABBCC");
    }

    #[test]
    fn test_is_dark_color() {
        assert!(is_dark_color("#000000"));
        assert!(is_dark_color("#000"));
        assert!(is_dark_color("black"));
        assert!(!is_dark_color("#FFFFFF"));
        assert!(!is_dark_color("#fff"));
        assert!(!is_dark_color("#FFFF00")); // yellow is bright
    }

    #[test]
    fn test_pixel_art_detection() {
       // Build 150 positioned divs simulating pixel art
        let mut html = String::from("<html><body>");
        for i in 0..150 {
            let color = if i % 2 == 0 { "#000000" } else { "#FFFFFF" };
            html.push_str(&format!(
                "<div style=\"float:left;width:3px;height:3px;margin-left:0px;background-color:{}\"></div>",
                color
            ));
        }
        html.push_str("</body></html>");

        let doc = Html::parse_document(&html);
        let pa = analyze_pixel_art_divs(&doc);

        assert!(pa.positioned_div_count >= 100);
        assert!(pa.unique_colors <= 3);
        assert!(pa.score >= 0.35, "Pixel art score {} < 0.35", pa.score);
    }

    #[test]
    fn test_normal_html_no_pixel_art() {
        let html = r#"<html><body>
        <div style="margin: 20px; padding: 10px;">
            <h1>Normal Newsletter</h1>
            <p>This is a regular email with lots of text content that should not trigger pixel art detection.</p>
        </div>
        </body></html>"#;

        let doc = Html::parse_document(html);
        let pa = analyze_pixel_art_divs(&doc);

        assert_eq!(pa.score, 0.0, "Normal HTML should have 0 pixel art score");
    }

    #[test]
    fn test_extract_px_value() {
        assert_eq!(
            extract_px_value("width: 4px; height: 4px", "width:"),
            Some(4.0)
        );
        assert_eq!(extract_px_value("width:3px", "width:"), Some(3.0));
        assert_eq!(extract_px_value("color: red", "width:"), None);
    }
}
