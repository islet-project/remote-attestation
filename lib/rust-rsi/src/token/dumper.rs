use super::*;


const COLUMN: usize = 30;


fn print_indent(indent: i32)
{
    for _ in 0..indent {
        print!("  ");
    }
}

fn print_claim(key: u32, claim: &Claim, indent: i32)
{
    print_indent(indent);

    if claim.present {
        match &claim.data {
            ClaimData::Int64(i) => println!("{:COLUMN$} (#{}) = {}", claim.title, key, i),
            ClaimData::Bool(b) => println!("{:COLUMN$} (#{}) = {}", claim.title, key, b),
            ClaimData::Bstr(v) => println!("{:COLUMN$} (#{}) = [{}]", claim.title, key, hex::encode(v)),
            ClaimData::Text(s) => println!("{:COLUMN$} (#{}) = \"{}\"", claim.title, key, s),
        }
    } else {
        let mandatory = if claim.mandatory { "mandatory " } else { "" };
        println!("* Missing {}claim with key: {} ({})",
                 mandatory, key, claim.title);
    }
}

fn print_cose_sign1(token_type: &str,
                    cose_sign1: &CoseSign1)
{
    println!("== {} Token cose:", token_type);
    println!("{:COLUMN$} = {:?}", "Protected header", cose_sign1.protected.header);
    println!("{:COLUMN$} = {:?}", "Unprotected header", cose_sign1.unprotected);
    //println!("{:COLUMN$} = [{}]", "Token payload", hex::encode(cose_sign1.payload.as_ref().unwrap_or(&Vec::new())));
    println!("{:COLUMN$} = [{}]", "Signature", hex::encode(&cose_sign1.signature));
    println!("== End of {} Token cose\n", token_type);
}

fn print_token_realm(claims: &RealmToken)
{
    print_cose_sign1("Realm", &claims.cose_sign1);

    println!("== Realm Token:");
    for (k, v) in &claims.token_claims {
        print_claim(*k, v, 0);
    }
    println!("{:COLUMN$} (#{})", "Realm measurements", CCA_REALM_EXTENSIBLE_MEASUREMENTS);
    for (k, v) in &claims.measurement_claims {
        print_claim(*k, v, 1);
    }
    println!("== End of Realm Token.\n\n");
}

pub fn print_token_platform(claims: &PlatformToken)
{
    print_cose_sign1("Platform", &claims.cose_sign1);

    println!("== Platform Token:");
    for (k, v) in &claims.token_claims {
        print_claim(*k, v, 0);
    }

    let mut count = 0;
    println!("{:COLUMN$} (#{})", "Platform SW components", CCA_PLAT_SW_COMPONENTS);
    for component in &claims.sw_component_claims {
        if component.present {
            println!("  SW component #{}:", count);
            for (k, v) in &component.claims {
                print_claim(*k, v, 2);
            }
            count += 1;
        }
    }
    println!("== End of Platform Token\n");
}

pub fn print_token(claims: &AttestationClaims)
{
    print_token_realm(&claims.realm_claims);
    print_token_platform(&claims.platform_claims);
}
