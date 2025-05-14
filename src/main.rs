use base64::{Engine as _, engine::general_purpose::STANDARD as Base64Standard};
use reqwest::blocking::Client;
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, ORIGIN, REFERER, TE,
    UPGRADE_INSECURE_REQUESTS, USER_AGENT,
};
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::borrow::Cow;
use std::io::{self, BufRead, BufReader, Write};
use std::time::Duration;
use url::Url;

use anyhow::{Context, Result, anyhow, bail};

const TARGET_URL_TO_PROXY: &str = "https://api.deepinfra.com/v1/openai/chat/completions";
const DEEPINFRA_API_BODY: &str = r#"{"model":"deepseek-ai/DeepSeek-Prover-V2-671B","messages":[{"role":"user","content":"hey"}],"stream":true,"stream_options":{"include_usage":true,"continuous_usage_stats":true}}"#;

const USER_AGENT_VAL: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0";
const ACCEPT_HTML_VAL: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const ACCEPT_EVENT_STREAM_VAL: &str = "text/event-stream";
const ACCEPT_LANG_VAL: &str = "en-US,en;q=0.5";
const CROXY_BASE_URL: &str = "https://www.croxyproxy.com";

const FORM_URLENCODED_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";

const SELECTOR_CSRF_TOKEN_MAIN_PAGE: &str = r#"form#request input[name="csrf"]"#;
const SELECTOR_SCRIPT_SERVER_SELECTOR: &str = "script#serverSelectorScript";
const SELECTOR_SCRIPT_INIT_SCRIPT: &str = "script#initScript";

#[derive(Deserialize, Debug, Clone)]
struct ServerInfo {
    id: u32,
    url: String,
    name: String,
}

fn hex_to_string(hex: &str) -> Result<String> {
    if hex.len() % 2 != 0 {
        bail!("Hex string has an odd number of characters: {}", hex);
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .with_context(|| format!("Failed to decode hex string: {}", hex))?;
    String::from_utf8(bytes).with_context(|| "Failed to convert hex-decoded bytes to UTF-8 string")
}

fn extract_attribute_from_html(
    html_body: &str,
    element_selector_str: &str,
    attribute_name: &str,
) -> Result<String> {
    let document = Html::parse_document(html_body);
    let selector = Selector::parse(element_selector_str)
        .map_err(|e| anyhow!("Failed to parse selector '{}': {}", element_selector_str, e))?;

    let element = document
        .select(&selector)
        .next()
        .ok_or_else(|| anyhow!("Element not found with selector: {}", element_selector_str))?;

    let value = element.value().attr(attribute_name).ok_or_else(|| {
        anyhow!(
            "Attribute '{}' not found on element selected by '{}'",
            attribute_name,
            element_selector_str
        )
    })?;
    Ok(value.to_string())
}

fn select_proxy_server(
    client: &Client,
    servers_page_html: &str,
    croxy_base_url_ref: &str,
) -> Result<ServerInfo> {
    println!("   Attempting to select a proxy server automatically...");
    let server_list_json_str = extract_attribute_from_html(
        servers_page_html,
        SELECTOR_SCRIPT_SERVER_SELECTOR,
        "data-ss",
    )
    .context("Failed to extract server list JSON string (data-ss)")?;

    let server_list_b64: Vec<String> =
        serde_json::from_str(&server_list_json_str).with_context(|| {
            format!(
                "Failed to parse server list JSON (data-ss). Content: {}",
                server_list_json_str
            )
        })?;

    if server_list_b64.is_empty() {
        bail!("Server list (data-ss) is empty.");
    }

    for s_b64 in server_list_b64 {
        let hex_encoded_json_bytes = Base64Standard
            .decode(&s_b64)
            .with_context(|| format!("Base64 decoding of server entry failed. Entry: {}", s_b64))?;

        let hex_encoded_json_str = String::from_utf8(hex_encoded_json_bytes)
            .with_context(|| "UTF8 conversion after Base64 decode failed for server entry.")?;

        let server_json_str = hex_to_string(&hex_encoded_json_str).with_context(|| {
            format!(
                "Hex to string decoding failed for server entry. Hex: {}",
                hex_encoded_json_str
            )
        })?;

        let server_info: ServerInfo = match serde_json::from_str(&server_json_str) {
            Ok(info) => info,
            Err(e) => {
                eprintln!(
                    "     [WARN] Failed to parse server JSON: {}. JSON: '{}'. Skipping.",
                    e, server_json_str
                );
                continue;
            }
        };

        println!(
            "     Testing server: ID {}, URL {}...",
            server_info.id, server_info.url
        );

        match client
            .get(&server_info.url)
            .header(REFERER, HeaderValue::from_str(croxy_base_url_ref)?)
            .header(ORIGIN, HeaderValue::from_str(croxy_base_url_ref)?)
            .timeout(Duration::from_secs(5))
            .send()
        {
            Ok(ping_res) => {
                let status = ping_res.status();
                if status.is_success() {
                    match ping_res.text() {
                        Ok(text) => {
                            if text.trim() == "OK" {
                                println!(
                                    "     Server ID {} ({}) responded OK. Selecting this server.",
                                    server_info.id, server_info.name
                                );
                                return Ok(server_info);
                            } else {
                                eprintln!(
                                    "     [WARN] Server ID {} pinged, but response was not 'OK': {}",
                                    server_info.id,
                                    text.trim()
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "     [WARN] Server ID {} pinged, but failed to read response body: {}",
                                server_info.id, e
                            );
                        }
                    }
                } else {
                    eprintln!(
                        "     [WARN] Server ID {} ping failed with status: {}",
                        server_info.id, status
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "     [WARN] Error pinging server ID {}: {}",
                    server_info.id, e
                );
            }
        }
    }

    bail!("Could not find a working proxy server after trying all options.")
}

fn main() -> Result<()> {
    let mut common_headers_for_croxy = HeaderMap::new();
    common_headers_for_croxy.insert(ACCEPT, HeaderValue::from_static(ACCEPT_HTML_VAL));
    common_headers_for_croxy.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(ACCEPT_LANG_VAL));
    common_headers_for_croxy.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    common_headers_for_croxy.insert(
        HeaderName::from_static("priority"),
        HeaderValue::from_static("u=0, i"),
    );
    common_headers_for_croxy.insert(TE, HeaderValue::from_static("trailers"));

    let client = Client::builder()
        .cookie_store(true)
        .user_agent(USER_AGENT_VAL)
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::default())
        .build()
        .context("Failed to build reqwest client")?;

    println!(
        "[1] Fetching main page and initial CSRF token from {}...",
        CROXY_BASE_URL
    );
    let mut headers_step1 = common_headers_for_croxy.clone();
    headers_step1.insert(
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("document"),
    );
    headers_step1.insert(
        HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("navigate"),
    );
    headers_step1.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("none"),
    );
    headers_step1.insert(
        HeaderName::from_static("sec-fetch-user"),
        HeaderValue::from_static("?1"),
    );

    let res1 = client
        .get(CROXY_BASE_URL)
        .headers(headers_step1)
        .send()
        .context("Step 1: Request to fetch main page failed")?;

    let status1 = res1.status();
    let html_body1 = res1
        .text()
        .context("Step 1: Failed to read response body")?;
    println!("   Status: {}", status1);
    if !status1.is_success() {
        bail!("[FAIL] Step 1: HTTP {}. Body: {}", status1, html_body1);
    }

    let csrf_token1 =
        extract_attribute_from_html(&html_body1, SELECTOR_CSRF_TOKEN_MAIN_PAGE, "value")
            .context("Step 1: Failed to extract CSRF token")?;
    println!("   CSRF Token 1: {}", csrf_token1);

    println!("\n[2] Posting to /servers to get server list and secondary CSRF token...");
    let servers_url_str = format!("{}/servers", CROXY_BASE_URL);
    let form_params2 = [("url", TARGET_URL_TO_PROXY), ("csrf", csrf_token1.as_str())];

    let mut headers_step2 = common_headers_for_croxy.clone();
    headers_step2.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(FORM_URLENCODED_CONTENT_TYPE),
    );
    headers_step2.insert(
        ORIGIN,
        HeaderValue::from_str(CROXY_BASE_URL)
            .context("Failed to create Origin header for Step 2")?,
    );
    headers_step2.insert(
        REFERER,
        HeaderValue::from_str(CROXY_BASE_URL)
            .context("Failed to create Referer header for Step 2")?,
    );
    headers_step2.insert(
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("document"),
    );
    headers_step2.insert(
        HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("navigate"),
    );
    headers_step2.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    headers_step2.insert(
        HeaderName::from_static("sec-fetch-user"),
        HeaderValue::from_static("?1"),
    );

    let res2 = client
        .post(&servers_url_str)
        .headers(headers_step2)
        .form(&form_params2)
        .send()
        .context("Step 2: Request to /servers failed")?;

    let status2 = res2.status();
    let html_body2 = res2
        .text()
        .context("Step 2: Failed to read response body from /servers")?;
    println!("   Status: {}", status2);
    if !status2.is_success() {
        bail!("[FAIL] Step 2: HTTP {}. Body: {}", status2, html_body2);
    }

    let csrf_token2_json_escaped =
        extract_attribute_from_html(&html_body2, SELECTOR_SCRIPT_SERVER_SELECTOR, "data-csrf")
            .context("Step 2: Failed to extract CSRF token (data-csrf)")?;

    let csrf_token2: String =
        serde_json::from_str(&csrf_token2_json_escaped).with_context(|| {
            format!(
                "Step 2: Failed to parse CSRF Token 2 from JSON. Value: '{}'",
                csrf_token2_json_escaped
            )
        })?;
    println!("   CSRF Token 2: {}", csrf_token2);

    println!("\n[3] Automatically selecting a proxy server...");
    let chosen_server_info = select_proxy_server(&client, &html_body2, CROXY_BASE_URL)
        .context("Step 3: Failed to select a proxy server")?;
    println!("   Selected Proxy Server ID: {}", chosen_server_info.id);

    println!("\n[4] Posting to /requests (client will follow redirect to __cpi.php)...");
    let requests_url_str = format!("{}/requests?fso=", CROXY_BASE_URL);

    let server_id_str = chosen_server_info.id.to_string();
    let form_params4 = [
        ("url", TARGET_URL_TO_PROXY),
        ("proxyServerId", server_id_str.as_str()),
        ("csrf", csrf_token2.as_str()),
        ("demo", "0"),
        ("frontOrigin", CROXY_BASE_URL),
    ];

    let mut headers_step4 = common_headers_for_croxy.clone();
    headers_step4.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(FORM_URLENCODED_CONTENT_TYPE),
    );
    headers_step4.insert(
        ORIGIN,
        HeaderValue::from_str(CROXY_BASE_URL)
            .context("Failed to create Origin header for Step 4")?,
    );
    headers_step4.insert(
        REFERER,
        HeaderValue::from_str(&servers_url_str)
            .context("Failed to create Referer header for Step 4")?,
    );
    headers_step4.insert(
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("document"),
    );
    headers_step4.insert(
        HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("navigate"),
    );
    headers_step4.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );

    let res_cpi = client
        .post(&requests_url_str)
        .headers(headers_step4)
        .form(&form_params4)
        .send()
        .context("Step 4: Request to /requests failed")?;

    let status_cpi = res_cpi.status();
    let cpi_url_after_redirect = res_cpi.url().clone();
    let cpi_page_html = res_cpi
        .text()
        .context("Step 4: Failed to read response body from __cpi.php")?;

    println!(
        "   Status after redirect (should be for __cpi.php): {}",
        status_cpi
    );
    println!("   URL after redirect: {}", cpi_url_after_redirect);

    if !status_cpi.is_success() {
        bail!(
            "[FAIL] Step 4 (loading __cpi.php): HTTP {}. Body: {}",
            status_cpi,
            cpi_page_html
        );
    }

    println!("\n[5] Parsing __cpi.php page content...");
    let data_r_b64_encoded =
        extract_attribute_from_html(&cpi_page_html, SELECTOR_SCRIPT_INIT_SCRIPT, "data-r")
            .context("Step 5: Failed to extract data-r attribute")?;
    println!(
        "   data-r (Base64 encoded final URL): {}",
        data_r_b64_encoded
    );

    let final_proxied_url_bytes = Base64Standard
        .decode(data_r_b64_encoded)
        .context("Step 6: Failed to Base64 decode data-r attribute")?;
    let final_proxied_url_str = String::from_utf8(final_proxied_url_bytes)
        .context("Step 6: Failed to convert decoded data-r to UTF-8 string")?;
    println!(
        "\n[6] Decoded final proxied URL for DeepInfra API: {}",
        final_proxied_url_str
    );

    let final_url_obj = Url::parse(&final_proxied_url_str).with_context(|| {
        format!(
            "Step 6: Failed to parse final proxied URL: {}",
            final_proxied_url_str
        )
    })?;

    match (cpi_url_after_redirect.host_str(), final_url_obj.host_str()) {
        (Some(cpi_host), Some(final_host)) => {
            if cpi_host != final_host {
                eprintln!(
                    "[INFO] Host for CPI page ({}) and final URL ({}) differ. This is typical for proxies.",
                    cpi_host, final_host
                );
            }
        }
        _ => {
            eprintln!(
                "[WARN] Could not extract host from CPI URL or final URL for comparison. This might indicate an issue."
            );
        }
    }

    println!(
        "\n[7] POSTing to DeepInfra API via proxy {} and streaming response...",
        final_proxied_url_str
    );

    let mut headers_step7 = HeaderMap::new();
    headers_step7.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VAL));
    headers_step7.insert(ACCEPT, HeaderValue::from_static(ACCEPT_EVENT_STREAM_VAL));
    headers_step7.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(ACCEPT_LANG_VAL));
    headers_step7.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
    headers_step7.insert(
        HeaderName::from_static("x-deepinfra-source"),
        HeaderValue::from_static("model-embed"),
    );
    headers_step7.insert(
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("empty"),
    );
    headers_step7.insert(
        HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("cors"),
    );
    headers_step7.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-site"),
    );
    headers_step7.insert(
        HeaderName::from_static("priority"),
        HeaderValue::from_static("u=0"),
    );
    headers_step7.insert(
        REFERER,
        HeaderValue::from_str(cpi_url_after_redirect.as_str())
            .context("Step 7: Failed to create Referer header")?,
    );

    let cpi_host_for_origin: Cow<str> = cpi_url_after_redirect
        .host_str()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| {
            eprintln!("[WARN] CPI redirect URL has no host, using CROXY_BASE_URL's host for Origin header as fallback");
            let croxy_parsed_url = Url::parse(CROXY_BASE_URL)
                .expect("Static CROXY_BASE_URL should be parsable");
            Cow::Owned(croxy_parsed_url.host_str()
                .expect("Static CROXY_BASE_URL should have a host")
                .to_string())
        });

    let cpi_origin_str = format!(
        "{}://{}",
        cpi_url_after_redirect.scheme(),
        cpi_host_for_origin.as_ref()
    );
    headers_step7.insert(
        ORIGIN,
        HeaderValue::from_str(&cpi_origin_str)
            .context("Step 7: Failed to create Origin header from CPI URL")?,
    );

    let res_final_stream = client
        .post(&final_proxied_url_str)
        .headers(headers_step7)
        .body(DEEPINFRA_API_BODY.to_string())
        .send()
        .context("Step 7: POST request to DeepInfra API via proxy failed")?;

    let status_final = res_final_stream.status();
    println!("   Status from DeepInfra API via proxy: {}", status_final);

    if !status_final.is_success() {
        let error_body = res_final_stream
            .text()
            .context("Step 7: Failed to read error response body from DeepInfra API")?;
        bail!(
            "[FAIL] Step 7 (DeepInfra POST): HTTP {}. Body: {}",
            status_final,
            error_body
        );
    }

    println!("   Streaming Response Body from DeepInfra API via proxy:");
    let reader = BufReader::new(res_final_stream);
    for line_result in reader.lines() {
        let line = line_result.context("Error reading line from stream")?;
        if line.starts_with("data: ") {
            let json_str = &line["data: ".len()..];
            if json_str.trim() == "[DONE]" {
                println!("data: [DONE]");
                break;
            }
            match serde_json::from_str::<JsonValue>(json_str) {
                Ok(json_chunk) => {
                    if let Some(content) = json_chunk
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|choices| choices.get(0))
                        .and_then(|first_choice| first_choice.get("delta"))
                        .and_then(|delta| delta.get("content"))
                        .and_then(|c| c.as_str())
                    {
                        print!("{}", content);
                        io::stdout().flush().context("Failed to flush stdout")?;
                    }

                    if let Some(finish_reason) = json_chunk
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|choices| choices.get(0))
                        .and_then(|first_choice| first_choice.get("finish_reason"))
                        .and_then(|fr| fr.as_str())
                    {
                        if finish_reason == "stop" {
                            println!("\n[STREAM FINISHED: stop reason]");
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "\n[WARN] Error parsing JSON chunk: {}. Line: '{}'",
                        e, json_str
                    );
                }
            }
        } else if !line.is_empty() {
            println!("{}", line);
        }
    }
    println!();

    Ok(())
}
