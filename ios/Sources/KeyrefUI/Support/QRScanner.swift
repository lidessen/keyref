// QR scanning for pairing (docs/ios-ui.md §2.8, §3.2): full-screen camera
// via AVCaptureMetadataOutput wrapped in UIViewRepresentable, torch toggle,
// and the degradation paths. Camera-permission-denied replaces the whole
// page with a Settings deep link — no photo-picker and no manual entry
// (§3.2). On hosts with no camera at all (the simulator) the page shows a
// simulator-only paste field so the flow stays walkable in development;
// that path is compiled out of device builds.
#if os(iOS)
import AVFoundation
import Combine
import SwiftUI
import UIKit

public final class QRScannerCoordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate, ObservableObject, @unchecked Sendable {
    public enum CameraState: Equatable, Sendable {
        case idle
        case permissionDenied
        case noCamera
        case running
    }

    /// Called on the main queue when a QR payload is decoded.
    public var onPayload: (@MainActor (String) -> Void)?

    /// Camera state, written on the main actor only.
    @Published public private(set) var state: CameraState = .idle

    private let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "app.keyref.qrscanner")
    private var deviceInput: AVCaptureDeviceInput?
    private var lastPayload: String?
    private var running = false

    public override init() {
        super.init()
    }

    /// The capture session for the preview layer.
    public var captureSession: AVCaptureSession { session }

    private func setState(_ s: CameraState) {
        Task { @MainActor in self.state = s }
    }

    public func start() {
        sessionQueue.async { [weak self] in
            guard let self else { return }
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .denied, .restricted:
                self.setState(.permissionDenied)
                return
            default:
                break
            }
            if self.deviceInput == nil {
                guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)
                        ?? AVCaptureDevice.default(for: .video) else {
                    self.setState(.noCamera)
                    return
                }
                do {
                    let input = try AVCaptureDeviceInput(device: device)
                    self.session.beginConfiguration()
                    if self.session.canAddInput(input) { self.session.addInput(input) }
                    self.deviceInput = input
                    let output = AVCaptureMetadataOutput()
                    if self.session.canAddOutput(output) {
                        self.session.addOutput(output)
                        output.setMetadataObjectsDelegate(self, queue: .main)
                        output.metadataObjectTypes = [.qr]
                    }
                    self.session.commitConfiguration()
                } catch {
                    self.setState(.noCamera)
                    return
                }
            }
            if !self.running {
                self.session.startRunning()
                self.running = true
            }
            self.setState(.running)
        }
    }

    public func stop() {
        sessionQueue.async { [weak self] in
            guard let self, self.running else { return }
            self.session.stopRunning()
            self.running = false
        }
    }

    public func setTorch(on: Bool) {
        sessionQueue.async { [weak self] in
            guard let device = self?.deviceInput?.device, device.hasTorch else { return }
            try? device.lockForConfiguration()
            device.torchMode = on ? .on : .off
            device.unlockForConfiguration()
        }
    }

    public func metadataOutput(_ output: AVCaptureMetadataOutput,
                               didOutput metadataObjects: [AVMetadataObject],
                               from connection: AVCaptureConnection) {
        guard let obj = metadataObjects.compactMap({ $0 as? AVMetadataMachineReadableCodeObject }).first,
              obj.type == .qr, let value = obj.stringValue, lastPayload != value else { return }
        lastPayload = value
        let callback = onPayload
        Task { @MainActor in callback?(value) }
    }
}

/// Camera preview wrapped for SwiftUI.
public struct CameraPreview: UIViewRepresentable {
    public let scanner: QRScannerCoordinator

    public init(scanner: QRScannerCoordinator) {
        self.scanner = scanner
    }

    public final class PreviewView: UIView {
        override public class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }

    public func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        let layer = view.previewLayer
        layer.session = scanner.captureSession
        layer.videoGravity = .resizeAspectFill
        return view
    }

    public func updateUIView(_ uiView: PreviewView, context: Context) {}
}
#endif
