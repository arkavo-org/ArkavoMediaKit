import Foundation

/// Media-specific DRM policy for TDF3 protected content
public struct MediaDRMPolicy: Sendable {
    /// Rental window configuration
    public let rentalWindow: RentalWindow?

    /// Maximum concurrent streams allowed
    public let maxConcurrentStreams: Int?

    /// Geographic restrictions (ISO 3166-1 alpha-2 codes)
    public let allowedRegions: Set<String>?
    public let blockedRegions: Set<String>?

    /// HDCP requirement level
    public let hdcpLevel: HDCPLevel?

    /// Minimum device security level required
    public let minSecurityLevel: DeviceSecurityLevel?

    /// Allow playback in virtual machines
    public let allowVirtualMachines: Bool

    /// Subscription tier requirement
    public let requiredSubscriptionTier: String?

    public enum HDCPLevel: String, Sendable, Codable {
        case none = "none"
        case type0 = "type0" // HDCP 1.x
        case type1 = "type1" // HDCP 2.2+
    }

    public enum DeviceSecurityLevel: String, Sendable, Codable {
        case low = "low"
        case medium = "medium"
        case high = "high"
    }

    public struct RentalWindow: Sendable, Codable {
        /// Time from purchase to first play (seconds)
        public let purchaseWindow: TimeInterval

        /// Time from first play to expiry (seconds)
        public let playbackWindow: TimeInterval

        public init(purchaseWindow: TimeInterval, playbackWindow: TimeInterval) {
            self.purchaseWindow = purchaseWindow
            self.playbackWindow = playbackWindow
        }
    }

    public init(
        rentalWindow: RentalWindow? = nil,
        maxConcurrentStreams: Int? = nil,
        allowedRegions: Set<String>? = nil,
        blockedRegions: Set<String>? = nil,
        hdcpLevel: HDCPLevel? = nil,
        minSecurityLevel: DeviceSecurityLevel? = nil,
        allowVirtualMachines: Bool = false,
        requiredSubscriptionTier: String? = nil
    ) {
        self.rentalWindow = rentalWindow
        self.maxConcurrentStreams = maxConcurrentStreams
        self.allowedRegions = allowedRegions
        self.blockedRegions = blockedRegions
        self.hdcpLevel = hdcpLevel
        self.minSecurityLevel = minSecurityLevel
        self.allowVirtualMachines = allowVirtualMachines
        self.requiredSubscriptionTier = requiredSubscriptionTier
    }

    /// Validate policy against session and context
    public func validate(
        session: MediaSession,
        firstPlayTimestamp: Date?,
        currentActiveStreams: Int,
        deviceInfo: DeviceInfo
    ) throws {
        // Check rental window
        if let rentalWindow, let firstPlay = firstPlayTimestamp {
            let elapsed = Date().timeIntervalSince(firstPlay)
            if elapsed > rentalWindow.playbackWindow {
                throw PolicyViolation.rentalWindowExpired
            }
        }

        // Check concurrency
        if let maxStreams = maxConcurrentStreams, currentActiveStreams >= maxStreams {
            throw PolicyViolation.concurrencyLimitExceeded
        }

        // Check geo-restrictions
        if let region = session.geoRegion {
            if let allowed = allowedRegions, !allowed.contains(region) {
                throw PolicyViolation.geoRestricted(region: region)
            }
            if let blocked = blockedRegions, blocked.contains(region) {
                throw PolicyViolation.geoRestricted(region: region)
            }
        }

        // Check device security
        if let minLevel = minSecurityLevel, deviceInfo.securityLevel.rawValue < minLevel.rawValue {
            throw PolicyViolation.insufficientDeviceSecurity
        }

        // Check virtual machine
        if !allowVirtualMachines && deviceInfo.isVirtualMachine {
            throw PolicyViolation.virtualMachineDetected
        }
    }
}

/// Device information for policy enforcement
public struct DeviceInfo: Sendable {
    public let securityLevel: MediaDRMPolicy.DeviceSecurityLevel
    public let isVirtualMachine: Bool
    public let hdcpCapability: MediaDRMPolicy.HDCPLevel

    public init(
        securityLevel: MediaDRMPolicy.DeviceSecurityLevel = .medium,
        isVirtualMachine: Bool = false,
        hdcpCapability: MediaDRMPolicy.HDCPLevel = .type0
    ) {
        self.securityLevel = securityLevel
        self.isVirtualMachine = isVirtualMachine
        self.hdcpCapability = hdcpCapability
    }
}

/// Policy violation errors
public enum PolicyViolation: Error, LocalizedError, Sendable {
    case rentalWindowExpired
    case concurrencyLimitExceeded
    case geoRestricted(region: String)
    case insufficientDeviceSecurity
    case virtualMachineDetected
    case subscriptionRequired(tier: String)

    public var errorDescription: String? {
        switch self {
        case .rentalWindowExpired:
            "Rental playback window has expired"
        case .concurrencyLimitExceeded:
            "Maximum concurrent streams exceeded"
        case let .geoRestricted(region):
            "Content not available in region: \(region)"
        case .insufficientDeviceSecurity:
            "Device security level insufficient"
        case .virtualMachineDetected:
            "Playback not allowed on virtual machines"
        case let .subscriptionRequired(tier):
            "Subscription tier required: \(tier)"
        }
    }
}

extension MediaDRMPolicy: Codable {}
extension DeviceInfo: Codable {}
