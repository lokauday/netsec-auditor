"""
Service for seeding built-in rule packs.
"""
import logging
from sqlalchemy.orm import Session

from app.models.rule_pack import RulePack
from app.models.rule import Rule, RuleSeverity, RuleCategory

logger = logging.getLogger(__name__)


def seed_rule_packs(db: Session) -> None:
    """
    Seed built-in rule packs with their rules.
    
    Creates the following packs:
    - Internet Exposure
    - Compliance Baseline
    - Crypto & VPN
    - Policy Hygiene
    """
    # Check if packs already exist
    existing_packs = db.query(RulePack).filter(RulePack.is_builtin == True).all()
    if existing_packs:
        logger.info(f"Built-in rule packs already exist ({len(existing_packs)} packs). Skipping seed.")
        return
    
    logger.info("Seeding built-in rule packs...")
    
    # Pack 1: Internet Exposure
    internet_pack = RulePack(
        name="Internet Exposure",
        description="Detects rules that expose internal resources to the internet or allow unrestricted access",
        category="internet_exposure",
        is_builtin=True,
        enabled=True,
    )
    db.add(internet_pack)
    db.flush()  # Get ID
    
    # Rules for Internet Exposure pack
    internet_rules = [
        {
            "name": "Permit Any Any Traffic",
            "description": "Detects ACL rules that permit any-to-any traffic, effectively bypassing security",
            "vendor": "cisco_asa",
            "category": RuleCategory.ACL,
            "severity": RuleSeverity.CRITICAL,
            "match_criteria": {
                "pattern": "permit ip any any",
                "pattern_type": "contains"
            }
        },
        {
            "name": "SSH Access from Internet",
            "description": "Detects SSH access rules from external sources (any/0.0.0.0)",
            "vendor": None,
            "category": RuleCategory.ACL,
            "severity": RuleSeverity.HIGH,
            "match_criteria": {
                "pattern": "permit tcp.*eq 22",
                "pattern_type": "regex"
            }
        },
        {
            "name": "RFC1918 Access from Outside",
            "description": "Detects inbound rules allowing access to private networks from outside",
            "vendor": None,
            "category": RuleCategory.ACL,
            "severity": RuleSeverity.HIGH,
            "match_criteria": {
                "pattern": "permit.*10\\.0\\.0\\.0|permit.*172\\.16\\.|permit.*192\\.168\\.",
                "pattern_type": "regex"
            }
        },
    ]
    
    for rule_data in internet_rules:
        rule = Rule(
            name=rule_data["name"],
            description=rule_data["description"],
            vendor=rule_data["vendor"],
            category=rule_data["category"],
            severity=rule_data["severity"],
            match_criteria=rule_data["match_criteria"],
            enabled=True,
            created_by=None,  # System-created
        )
        db.add(rule)
        db.flush()
        internet_pack.rules.append(rule)
    
    # Pack 2: Compliance Baseline
    compliance_pack = RulePack(
        name="Compliance Baseline",
        description="Common compliance checks for security standards (PCI-DSS, HIPAA, etc.)",
        category="compliance",
        is_builtin=True,
        enabled=True,
    )
    db.add(compliance_pack)
    db.flush()
    
    compliance_rules = [
        {
            "name": "Weak Crypto Suite",
            "description": "Detects weak cryptographic algorithms or protocols",
            "vendor": None,
            "category": RuleCategory.CRYPTO,
            "severity": RuleSeverity.HIGH,
            "match_criteria": {
                "pattern": "md5|sha1|des|rc4|ssl.*2\\.0|ssl.*3\\.0|tls.*1\\.0",
                "pattern_type": "regex"
            }
        },
        {
            "name": "Default Credentials",
            "description": "Detects use of default usernames or passwords",
            "vendor": None,
            "category": RuleCategory.AUTHENTICATION,
            "severity": RuleSeverity.CRITICAL,
            "match_criteria": {
                "pattern": "username.*admin.*password|username.*cisco.*password|default.*password",
                "pattern_type": "regex"
            }
        },
    ]
    
    for rule_data in compliance_rules:
        rule = Rule(
            name=rule_data["name"],
            description=rule_data["description"],
            vendor=rule_data["vendor"],
            category=rule_data["category"],
            severity=rule_data["severity"],
            match_criteria=rule_data["match_criteria"],
            enabled=True,
            created_by=None,
        )
        db.add(rule)
        db.flush()
        compliance_pack.rules.append(rule)
    
    # Pack 3: Crypto & VPN
    crypto_pack = RulePack(
        name="Crypto & VPN",
        description="VPN and cryptographic configuration security checks",
        category="crypto_vpn",
        is_builtin=True,
        enabled=True,
    )
    db.add(crypto_pack)
    db.flush()
    
    crypto_rules = [
        {
            "name": "Weak VPN Crypto",
            "description": "Detects weak VPN encryption algorithms",
            "vendor": None,
            "category": RuleCategory.VPN,
            "severity": RuleSeverity.HIGH,
            "match_criteria": {
                "pattern": "encryption.*des|encryption.*md5|encryption.*sha1",
                "pattern_type": "regex"
            }
        },
        {
            "name": "VPN Without Authentication",
            "description": "Detects VPN configurations without proper authentication",
            "vendor": None,
            "category": RuleCategory.VPN,
            "severity": RuleSeverity.MEDIUM,
            "match_criteria": {
                "pattern": "crypto.*map.*no.*authentication|crypto.*isakmp.*no.*auth",
                "pattern_type": "regex"
            }
        },
    ]
    
    for rule_data in crypto_rules:
        rule = Rule(
            name=rule_data["name"],
            description=rule_data["description"],
            vendor=rule_data["vendor"],
            category=rule_data["category"],
            severity=rule_data["severity"],
            match_criteria=rule_data["match_criteria"],
            enabled=True,
            created_by=None,
        )
        db.add(rule)
        db.flush()
        crypto_pack.rules.append(rule)
    
    # Pack 4: Policy Hygiene
    hygiene_pack = RulePack(
        name="Policy Hygiene",
        description="Detects policy hygiene issues like redundant rules, shadowed rules, and unused objects",
        category="policy_hygiene",
        is_builtin=True,
        enabled=True,
    )
    db.add(hygiene_pack)
    db.flush()
    
    # Note: Policy hygiene rules are detected algorithmically in the audit service,
    # so we don't create explicit rules here. The pack serves as a category marker.
    # We could add rules that flag specific hygiene patterns if needed.
    
    db.commit()
    logger.info("Built-in rule packs seeded successfully")


def ensure_rule_packs_seeded(db: Session) -> None:
    """Ensure rule packs are seeded (called on startup)."""
    try:
        seed_rule_packs(db)
    except Exception as e:
        logger.error(f"Error seeding rule packs: {e}", exc_info=True)

