// Onboarding and recovery flow models (docs/ios-ui.md §2.2, §2.12, §2.13):
// vault creation with the show-once recovery code and the full group
// backfill check, plus the takeover / local-rebuild flows that share the
// same screen skeleton (§2.13 lists the three copy differences).
import Foundation
import KeyrefCore

// MARK: - group backfill (§2.2 校验抄写)

/// Pure state machine for the 分组回填 page: sequential input, auto-advance,
/// whole-blob paste with normalization, per-group red/green marking.
@Observable
@MainActor
public final class RecoveryBackfillModel {
    public let targetGroups: [String]
    /// User input per group (raw text; comparison is normalized).
    public var inputs: [String]
    /// nil = untouched; true = matches; false = mismatch (标红).
    public private(set) var results: [Bool?]
    public private(set) var allMatched = false
    public private(set) var completed = false

    public var focusIndex: Int = 0

    public init(targetGroups: [String]) {
        self.targetGroups = targetGroups
        self.inputs = Array(repeating: "", count: targetGroups.count)
        self.results = Array(repeating: nil, count: targetGroups.count)
    }

    public var errorMessage: String? {
        allMatched ? nil : "有一组和屏幕上的不一致，请对照你抄写的那份修改。"
    }

    /// A mismatched group stays red and keeps the cursor (§2.2).
    public var firstMismatchIndex: Int? {
        results.firstIndex(of: false)
    }

    /// Handles one group's text change. Pasting a whole blob into any field
    /// splits it across all groups automatically.
    public func update(group index: Int, raw: String) {
        guard index >= 0, index < targetGroups.count else { return }
        let cleaned = raw.replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")
        // 整段粘贴（自动去掉空格与连字符、按组拆分）。
        if cleaned.count > targetGroups[index].count {
            let groups = RecoveryCodeGroups.parsePasted(raw)
            if groups.count > 1 || (groups.count == 1 && groups[0].count > targetGroups[index].count) {
                applyPasted(groups)
                return
            }
        }
        let trimmed = String(cleaned.prefix(targetGroups[index].count))
        inputs[index] = trimmed
        if trimmed.count < targetGroups[index].count {
            results[index] = nil
            allMatched = false
            return
        }
        // 写满一组自动跳下一组；Crockford 归一化（0/O、1/I/L）。
        let ok = RecoveryCodeGroups.normalize(trimmed) == RecoveryCodeGroups.normalize(targetGroups[index])
        results[index] = ok
        if ok {
            if index + 1 < targetGroups.count {
                focusIndex = index + 1
            }
            recheck()
        } else {
            allMatched = false
        }
    }

    func applyPasted(_ groups: [String]) {
        for (i, group) in groups.enumerated() where i < targetGroups.count {
            inputs[i] = String(group.prefix(targetGroups[i].count))
            if inputs[i].count == targetGroups[i].count {
                results[i] = RecoveryCodeGroups.normalize(inputs[i])
                    == RecoveryCodeGroups.normalize(targetGroups[i])
            } else {
                results[i] = nil
            }
        }
        recheck()
        if let firstEmpty = results.firstIndex(of: nil) {
            focusIndex = firstEmpty
        }
    }

    func recheck() {
        allMatched = results.allSatisfy { $0 == true }
        if allMatched, !completed {
            completed = true
        }
    }
}

// MARK: - create vault flow (§2.2)

@Observable
@MainActor
public final class CreateVaultModel {
    public enum Step: Equatable, Sendable {
        case prerequisites
        case generating
        case recoveryCode
        case backfill
        case done
    }

    public let backend: any AppBackend
    public let haptics: any Haptics

    public private(set) var step: Step = .prerequisites
    public private(set) var prerequisites: [Prerequisite] = []
    public private(set) var draft: CreatedVaultDraft?
    public private(set) var generating = false
    public private(set) var generationLine = "正在生成安全隔区密钥…"
    public private(set) var uploadFailed = false
    /// 同步状态 shown on the done page (上传中 / 已同步).
    public private(set) var uploaded = false

    public private(set) var backfill: RecoveryBackfillModel?

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    public func loadPrerequisites() {
        prerequisites = backend.checkPrerequisites()
    }

    /// 缺哪项给哪项的系统设置深链（§2.2）。
    public var missingPrerequisites: [Prerequisite] {
        prerequisites.filter { !$0.satisfied }
    }

    public var canProceedFromPrerequisites: Bool {
        !prerequisites.isEmpty && prerequisites.allSatisfy { $0.satisfied }
    }

    public func startGeneration() async {
        generating = true
        step = .generating
        defer { generating = false }
        do {
            let draft = try await backend.prepareCreation(label: "这台 iPhone")
            self.draft = draft
            backfill = RecoveryBackfillModel(targetGroups: draft.recoveryGroups)
            step = .recoveryCode
            haptics.fire(.success)
        } catch {
            step = .prerequisites
        }
    }

    public func beginBackfill() {
        step = .backfill
    }

    /// 全部匹配：成功触感 + 进入完成页（§2.2）。
    public func finishBackfill() {
        guard backfill?.allMatched == true else { return }
        haptics.fire(.success)
        step = .done
    }

    /// 上传失败（网络、rate_limited、工作量证明失败）→ 错误态 + 重试；
    /// 重试不重新生成恢复码（§2.2）。
    public func upload() async {
        guard let draft else { return }
        do {
            try await backend.uploadCreatedVault(draft)
            uploaded = true
            uploadFailed = false
        } catch {
            uploadFailed = true
        }
    }
}

// MARK: - recovery flows (§2.12 takeover, §2.13 local rebuild)

@Observable
@MainActor
public final class RecoveryFlowModel {
    public enum Phase: Equatable, Sendable {
        case intro
        case input
        case preparing
        case confirmCommit     // 提交接管前的一次警报（仅接管）
        case running
        case done
        case repairGuide       // 重新配对指引（仅接管）
        case failed(message: String)
    }

    public enum Mode: Equatable, Sendable {
        case takeover
        case localRebuild

        var recoveryMode: RecoveryMode {
            self == .takeover ? .takeover : .localRebuild
        }
    }

    public let backend: any AppBackend
    public let haptics: any Haptics
    public let mode: Mode

    public private(set) var phase: Phase = .intro
    public var codeInput = ""
    public private(set) var inputError: String?
    public private(set) var preparation: RecoveryPreparation?
    public private(set) var currentStep: RecoveryStep?
    public private(set) var rotationRemaining = 0
    public private(set) var summary: TakeoverSummary?
    /// 接管提交是不可回退点；生效前可取消，生效后只能继续（§2.12）。
    public private(set) var commitStarted = false

    public init(backend: any AppBackend, haptics: any Haptics, mode: Mode) {
        self.backend = backend
        self.haptics = haptics
        self.mode = mode
    }

    /// 与 2.2 回填同一套分组输入控件：粘贴自动归一。
    public func handleCodeInput(_ raw: String) {
        codeInput = raw
        inputError = nil
    }

    public func submitCode() async {
        let code = codeInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else { return }
        phase = .preparing
        do {
            let prep = try await backend.prepareRecovery(code: code, mode: mode.recoveryMode)
            preparation = prep
            phase = mode == .takeover ? .confirmCommit : .running
        } catch let e as RecoveryInputError {
            phase = .input
            switch e {
            case .badCode:
                inputError = "恢复码不正确。"
            case .vaultNotFound:
                inputError = "在当前服务器上找不到这个保险库。"
            case .rateLimited:
                inputError = "尝试太频繁，请稍后再试。"
            case .network(let detail):
                inputError = detail
            }
        } catch {
            phase = .input
            inputError = "出了点问题，请稍后再试。"
        }
    }

    public func commit() async {
        guard let prep = preparation else { return }
        commitStarted = true
        phase = .running
        do {
            let summary = try await backend.commitRecovery(prep) { [weak self] step in
                guard let self else { return }
                Task { @MainActor in
                    self.currentStep = step
                    if case .rotateItems(let remaining) = step {
                        self.rotationRemaining = remaining
                    }
                }
            }
            self.summary = summary
            haptics.fire(.success)
            phase = .done
        } catch {
            haptics.fire(.error)
            if commitStarted {
                // 提交接管成功后失败（下载中断）→ 从断点继续（§2.12 失败态）。
                phase = .failed(message: "接管已生效，密文还在下载。重进后从断点继续。")
            } else {
                phase = .failed(message: "接管没有完成，没有提交任何更改。请重试。")
            }
        }
    }

    public func cancel() {
        guard !commitStarted else { return }
        phase = .intro
        codeInput = ""
        preparation = nil
    }

    // View-facing transitions.
    public func goToInput() { phase = .input }
    public func goToRepairGuide() { phase = .repairGuide }
    public func retryFromFailure() {
        phase = commitStarted ? .running : .input
    }
}
