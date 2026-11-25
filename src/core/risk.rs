use serde::Deserialize;

/// Overall risk classification of an analyzed indicator.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl RiskLevel {
    /// Maps a 0-100 risk score onto a level.
    pub fn from_score(score: u8) -> Self {
        match score {
            90..=u8::MAX => Self::Critical,
            70..=89 => Self::High,
            40..=69 => Self::Medium,
            _ => Self::Low,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Unknown => "Unknown",
        }
    }

    /// Position on the Low → Critical scale (Unknown has no position).
    pub fn rank(self) -> Option<usize> {
        match self {
            Self::Low => Some(0),
            Self::Medium => Some(1),
            Self::High => Some(2),
            Self::Critical => Some(3),
            Self::Unknown => None,
        }
    }

    /// Ordered scale used by the severity meter.
    pub const SCALE: [RiskLevel; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];
}

/// How confident the analysis is in its own verdict.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bands() {
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(90), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(78), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(45), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(5), RiskLevel::Low);
    }
}
