import SystemExtensions

extension ContainerController {
    func ensureSystemExtensionActivated(completion: @escaping (Bool) -> Void) {
        systemExtensionActivationCompletions.append(completion)
        guard !systemExtensionActivationInFlight else {
            log("system extension activation already in flight")
            return
        }

        systemExtensionActivationInFlight = true
        log("submitting system extension activation request for \(extensionBundleId)")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func finishSystemExtensionActivation(success: Bool, detail: String) {
        systemExtensionActivationInFlight = false
        let completions = systemExtensionActivationCompletions
        systemExtensionActivationCompletions.removeAll()
        log(detail)
        for completion in completions {
            completion(success)
        }
    }
}

extension ContainerController: OSSystemExtensionRequestDelegate {
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log("system extension approval required for \(request.identifier)")
        setStatus(status: .disconnected, detail: "approve system extension in System Settings")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        log(
            "replacing system extension \(existing.bundleShortVersion) with \(ext.bundleShortVersion)"
        )
        return .replace
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        finishSystemExtensionActivation(
            success: true,
            detail: "system extension activation finished with result=\(result.rawValue)"
        )
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        logError("system extension activation failed", error)
        finishSystemExtensionActivation(
            success: false, detail: "system extension activation failed")
    }
}
