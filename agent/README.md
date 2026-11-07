# secagent: AI Security Agent

Agent tự xây dựng bằng Function Calling, dùng để review bảo mật Pull Request của MediCare HMS. Agent chạy **sau** các công cụ quét (Semgrep, CodeQL, Bandit, Trivy, Gitleaks, Checkov, zizmor) và làm ba việc:

1. **Thẩm định** từng phát hiện của công cụ quét: `TP`, `FP` hoặc `NEEDS_REVIEW`, kèm lý do và bằng chứng trích từ mã nguồn.
2. **Săn thêm** lỗ hổng mà công cụ quét bỏ sót trong phần code PR thay đổi: phân quyền, IDOR, fail-open, vi phạm quy tắc R-01..R-15.
3. **Đề xuất bản vá** (unified diff) và kiểm chứng bản vá: áp vào bản sao tạm, chạy test và Semgrep.

Thiết kế nằm ở spec mục 4 (`docs/superpowers/specs/2026-11-07-devsecops-ai-agent-design.md`). Giao diện với pipeline là Hợp đồng 2 (`docs/superpowers/plans/2026-11-07-00-roadmap.md`).

## Cài đặt và chạy thử trên máy

```bash
cd agent && uv sync --locked          # Python 3.12, uv
export LLM_API_KEY=...                # key của nhà cung cấp đã chọn (mặc định DeepSeek)

# chạy từ gốc repo; sarif/ chứa file SARIF của các công cụ quét
uv run --project agent secagent --mode cli --repo . \
  --base origin/main --head HEAD --sarif-dir sarif --out out
uv run --project agent secagent-validate --out out --repo .   # kiểm chứng bản vá (không cần key)
```

`--mode cli` in ra từng bước suy luận và từng lần gọi công cụ, dùng khi demo. `--mode ci` và `--mode benchmark` chỉ in một dòng tóm tắt.

Muốn có SARIF trên máy, chạy `bash security/scan-local.sh sarif HEAD` (CodeQL chỉ chạy trên CI).

## Chọn nhà cung cấp LLM

Agent **không gắn cứng với DeepSeek**. Đổi nhà cung cấp bằng biến môi trường; trên GitHub đặt bằng biến repo (`gh variable set LLM_PROVIDER --body anthropic`), còn key luôn là secret `LLM_API_KEY`.

| `LLM_PROVIDER` | Model mặc định | Ghi chú |
|---|---|---|
| `deepseek` (mặc định) | `deepseek-chat` | `--thinking` chuyển sang `deepseek-reasoner`. Có sẵn đơn giá |
| `openai` | `gpt-5-mini` | Không gửi `temperature`. `--thinking` gửi `reasoning_effort="high"` |
| `gemini` | `gemini-2.5-flash` | Qua endpoint tương thích OpenAI của Google. `--thinking` gửi `reasoning_effort="high"` |
| `anthropic` | `claude-opus-5-5` | Dùng SDK `anthropic` gốc. Thinking luôn bật; `--thinking` đặt effort `high`. Bật refusal fallback phía server và prompt caching. Có sẵn đơn giá |
| `openai-compatible` | (bắt buộc `LLM_MODEL`) | OpenRouter, Ollama, LM Studio…: bắt buộc `LLM_BASE_URL` |

Các biến khác:

| Biến | Ý nghĩa |
|---|---|
| `LLM_MODEL` | Ghi đè model. Tên mặc định trong bảng trên có thể cũ dần theo thời gian |
| `LLM_BASE_URL` | Ghi đè endpoint (proxy, gateway) |
| `LLM_TEMPERATURE` | Số thực, hoặc `none` để không gửi. Mặc định 0 nếu nhà cung cấp hỗ trợ. Claude không nhận tham số này |
| `LLM_PRICE_IN_PER_M` / `LLM_PRICE_OUT_PER_M` | Đơn giá USD cho 1 triệu token, dùng để tính `cost_usd` (RQ4) |

Đổi nhà cung cấp không làm đổi kết quả của gate: gate chỉ đọc `report.json`.

## Tham số

| Tham số | Ý nghĩa |
|---|---|
| `--base`, `--head` | Commit gốc và commit của PR; diff được tính từ merge base, giống quality gate |
| `--sarif-dir` | Thư mục `*.sarif`. Tên công cụ lấy theo tên file |
| `--requirements` | `docs/security-requirements.md` (các quy tắc R-xx) |
| `--strategy single-shot` | Ablation C3: một lần gọi, không có công cụ điều tra |
| `--no-requirements` | Ablation C4: không có tài liệu quy tắc nghiệp vụ |
| `--no-ast-tools` | Ablation C5: bỏ `list_routes`, `get_function`, `find_callers` |
| `--thinking` | Cấu hình C2-thinking |
| `--model`, `--time-budget-s` | Ghi đè model; ngân sách thời gian (mặc định 360 s) |

## Đầu ra (`out/`)

| File | Nội dung |
|---|---|
| `report.json` | Kết luận cho từng cụm phát hiện, theo đúng schema spec 4.3 cộng `finding_ids`. Quality gate đọc file này |
| `report.md` | Comment báo cáo trên PR (tiếng Việt) |
| `agent.sarif` | Lỗ hổng do Agent tự tìm, upload lên tab Security (category `ai-agent`) |
| `review.json` | Review với các comment `suggestion` để sửa bằng một cú bấm |
| `trace.jsonl` | Nhật ký từng lần gọi LLM và công cụ, đã che secret |

Mã thoát: `0` là chạy xong; `2` là Agent thất bại, khi đó gate quay về chế độ `traditional`.

## Cách hoạt động

1. **Tiền xử lý** (không dùng LLM):
   - đọc SARIF và tính finding id **giống hệt** quality gate (có test hợp đồng so với `security/gate/gate.py`);
   - gộp các phát hiện cùng file, lệch ±3 dòng và cùng nhóm CWE thành một cụm `F1`, `F2`…;
   - đánh dấu cụm nằm trong diff và che secret.
2. **Phiên review**:
   - mỗi lô tối đa 15 cụm có một vòng lặp Function Calling, giới hạn `min(10 + 3 × số cụm, 60)` lần gọi;
   - chỉ lô đầu được săn lỗi mới;
   - chạm giới hạn thì có thêm một lượt để nộp kết luận, và cụm còn thiếu thành `NEEDS_REVIEW`, không bao giờ thành `FP`.
3. **Kiểm tra**:
   - cụm chưa có kết luận được hỏi lại một lần;
   - bằng chứng phải khớp với code thật, kết luận `FP` phải có bằng chứng; không đạt thì thành `NEEDS_REVIEW`.
4. **Báo cáo** và **kiểm chứng bản vá**: tối đa 2 bản vá, mức nghiêm trọng cao nhất trước.

## Ranh giới bảo mật

- **Công cụ chỉ đọc.** Không có công cụ ghi file hay chạy lệnh. Đường dẫn bị giới hạn trong repo; `.git/`, `.env*`, `*.pem`, `*.key` bị từ chối.
- **Code của PR là dữ liệu.** Mọi nội dung lấy từ PR được bọc trong `<untrusted-code>`. Prompt nói rõ đó không phải chỉ thị, và thẻ đóng nằm trong file bị vô hiệu hóa.
- **Che secret.** Dòng mà Gitleaks báo bị che nguyên dòng. Các mẫu key, token, mật khẩu bị che trong mọi thứ gửi LLM và trong `report.*` lẫn `trace.jsonl`.
- **Prompt injection không gỡ được việc chặn.** Kết luận `FP` phải có bằng chứng khớp code thật. Gate chỉ miễn chặn Critical khi có label `security-reviewed`. Sửa `agent/**` cũng cần label đó.
- **Trên CI:**
  - Bước gọi LLM là bước duy nhất có `LLM_API_KEY`. Bước này chạy code Agent lấy từ PR (vì vậy sửa `agent/**` cần label `security-reviewed`), nhưng không chạy ứng dụng hay test của PR. `report.json` được upload (artifact `agent-report`) ngay sau bước này, và quality gate chỉ đọc artifact đó.
  - Kiểm chứng bản vá chạy ở job riêng `validate-patches`. Job này chạy test của PR nên không tham chiếu secret nào và không lưu uv cache; kết quả của nó (artifact `agent-validation`) chỉ để hiển thị, gate không dùng.
  - Job `agent-comment` không checkout code. Job này chỉ cập nhật comment và review của chính bot, và luôn gửi review dạng `COMMENT` (Agent không bao giờ approve PR).
- **Bằng chứng cho FP.** Kết luận `FP` phải trích ít nhất một đoạn mã thật (≥ 10 ký tự) tại vị trí phát hiện (±20 dòng) hoặc trong file liên quan theo luồng dữ liệu; với phát hiện SCA thì chỉ cần trích được mã thật, ví dụ nơi import. Không đạt thì kết luận thành `NEEDS_REVIEW`.
- **Bản vá không được tin số dòng.** Dòng bị xóa và dòng ngữ cảnh của bản vá phải khớp nội dung thật; nếu không, bản vá không được tính là đã kiểm chứng và không thành gợi ý sửa.
- **Chỉ thẩm định phát hiện trong phần PR thay đổi**, đúng tập mà quality gate xét, và xét phát hiện nghiêm trọng nhất trước.
- **Dữ liệu gửi đi.** Code của PR được gửi cho nhà cung cấp LLM đã chọn; cần cân nhắc điều này trong môi trường bệnh viện thật (spec mục 5.7).

## Phát triển

```bash
cd agent && uv run --locked pytest -q && uv run --locked ruff check .
```

Test không gọi LLM thật. `tests/fakes.py` có `ScriptedLLM` (phát lại phản hồi theo kịch bản), và client HTTP được giả lập bằng `httpx2.MockTransport`. Secret giả trong test được ghép lúc chạy, để Gitleaks không coi chúng là secret thật.
