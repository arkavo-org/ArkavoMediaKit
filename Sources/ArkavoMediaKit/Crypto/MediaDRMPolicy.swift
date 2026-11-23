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

    public enum HDCPLevel: String, Sendable, Codable, Comparable {
        case none = "none"
        case type0 = "type0" // HDCP 1.x
        case type1 = "type1" // HDCP 2.2+

        public var rank: Int {
            switch self {
            case .none: 0
            case .type0: 1
            case .type1: 2
            }
        }

        public static func < (lhs: HDCPLevel, rhs: HDCPLevel) -> Bool {
            lhs.rank < rhs.rank
        }
    }

    public enum DeviceSecurityLevel: String, Sendable, Codable, Comparable {
        case low = "low"
        case medium = "medium"
        case high = "high"

        public var rank: Int {
            switch self {
            case .low: 0
            case .medium: 1
            case .high: 2
            }
        }

        public static func < (lhs: DeviceSecurityLevel, rhs: DeviceSecurityLevel) -> Bool {
            lhs.rank < rhs.rank
        }
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
        let now = Date()

        // Check rental window (both purchase window and playback window)
        if let rentalWindow {
            let purchaseDate: Date
            if let purchasedAtString = session.metadata["purchasedAt"] {
                guard let parsed = Self.parseISO8601Date(purchasedAtString) else {
                    throw PolicyViolation.rentalWindowExpired
                }
                purchaseDate = parsed
            } else {
                purchaseDate = session.createdAt
            }

            if let firstPlay = firstPlayTimestamp {
                if firstPlay.timeIntervalSince(purchaseDate) > rentalWindow.purchaseWindow {
                    throw PolicyViolation.rentalWindowExpired
                }
                let elapsed = now.timeIntervalSince(firstPlay)
                if elapsed > rentalWindow.playbackWindow {
                    throw PolicyViolation.rentalWindowExpired
                }
            } else {
                let elapsedSincePurchase = now.timeIntervalSince(purchaseDate)
                if elapsedSincePurchase > rentalWindow.purchaseWindow {
                    throw PolicyViolation.rentalWindowExpired
                }
            }
        }

        // Check concurrency (currentActiveStreams includes the current active session, so allow up to maxStreams inclusive)
        if let maxStreams = maxConcurrentStreams, maxStreams <= 0 || currentActiveStreams > maxStreams {
            throw PolicyViolation.concurrencyLimitExceeded
        }

        // Check geo-restrictions (fail closed when allowedRegions or non-empty blockedRegions is set and geoRegion is nil)
        if let allowed = allowedRegions {
            guard let region = session.geoRegion else {
                throw PolicyViolation.geoRestricted(region: "unknown")
            }
            if !allowed.contains(region) {
                throw PolicyViolation.geoRestricted(region: region)
            }
        }
        if let blocked = blockedRegions, !blocked.isEmpty {
            guard let region = session.geoRegion else {
                throw PolicyViolation.geoRestricted(region: "unknown")
            }
            if blocked.contains(region) {
                throw PolicyViolation.geoRestricted(region: region)
            }
        }

        // Check HDCP requirement using numeric rank
        if let requiredHDCP = hdcpLevel, deviceInfo.hdcpCapability < requiredHDCP {
            throw PolicyViolation.insufficientHDCP(required: requiredHDCP)
        }

        // Check device security using numeric rank (never lexicographic string comparison)
        if let minLevel = minSecurityLevel, deviceInfo.securityLevel < minLevel {
            throw PolicyViolation.insufficientDeviceSecurity
        }

        // Check virtual machine
        if !allowVirtualMachines && deviceInfo.isVirtualMachine {
            throw PolicyViolation.virtualMachineDetected
        }

        // Check subscription tier requirement
        if let requiredTier = requiredSubscriptionTier {
            let actualTier = session.metadata["subscriptionTier"]
            guard actualTier == requiredTier else {
                throw PolicyViolation.subscriptionRequired(tier: requiredTier)
            }
        }
    }

    private static func parseISO8601Date(_ string: String) -> Date? {
        let standard = ISO8601DateFormatter()
        if let date = standard.date(from: string) {
            return date
        }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: string)
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
public enum PolicyViolation: Error, LocalizedError, Sendable, Equatable {
    case rentalWindowExpired
    case concurrencyLimitExceeded
    case geoRestricted(region: String)
    case insufficientDeviceSecurity
    case insufficientHDCP(required: MediaDRMPolicy.HDCPLevel)
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
        case let .insufficientHDCP(required):
            "HDCP level insufficient (required: \(required.rawValue))"
        case .virtualMachineDetected:
            "Playback not allowed on virtual machines"
        case let .subscriptionRequired(tier):
            "Subscription tier required: \(tier)"
        }
    }
}

extension MediaDRMPolicy: Codable {}
extension DeviceInfo: Codable {}
