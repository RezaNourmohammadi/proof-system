use serde::{Deserialize, Serialize};

use std::option::Option;

// #[derive(Debug, Deserialize)]
// struct UserProfile {
//     wallet_address: Option<String>, // TODO: Change to Ethereum address
//     residence_country: Option<String>,
//     residence_province: Option<String>,
//     residence_city: Option<String>,
//     gender: Option<String>,
//     date_of_birth: Option<String>,
//     language_primary: Option<String>,
//     employment_status: Option<String>,
//     employment_industry: Option<u32>,
//     marital_status: Option<String>,
//     education: Option<String>,
//     household_income: Option<String>,
//     first_name: String,
//     middle_name: Option<String>,
//     last_name: String,
//     user_name: Option<String>,
//     email_address: Option<String>,
//     mobile_number: Option<u64>,
//     mobile_country_code: Option<String>,
//     avatar: Option<String>,
//     language_others: Option<Vec<String>>,
// }
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserProfile {
    pub wallet_address: String,
    pub first_name: String,
    pub last_name: String,
    pub email_address: Option<String>,
}

impl TryFrom<&str> for UserProfile {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parts = value.split(", ");
        // get UserProfile from parts
        let wallet_address = parts.next().ok_or("missing wallet_address")?.to_string();
        let first_name = parts.next().ok_or("missing first_name")?.to_string();
        let last_name = parts.next().ok_or("missing last_name")?.to_string();
        let email_address = parts.next().map(|s| s.to_string());
        Ok(UserProfile {
            wallet_address,
            first_name,
            last_name,
            email_address,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn deserialize_profile() {
        let profile: UserProfile = "0x53e16f6d33c1809c14ba489a6917e9de849ab20c, tom, hanks"
            .try_into()
            .unwrap();
        assert_eq!(
            profile.wallet_address,
            "0x53e16f6d33c1809c14ba489a6917e9de849ab20c"
        );
        assert_eq!(profile.first_name, "tom");
        assert_eq!(profile.last_name, "hanks");
    }
}
