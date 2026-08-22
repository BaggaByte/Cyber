import os
from database import SessionLocal
from models import User, Organization
from auth import get_password_hash

def create_default():
    """
    Creates a default admin user — only runs when CREATE_DEFAULT_ADMIN=true.
    Password must be supplied via DEFAULT_ADMIN_PASSWORD env var.
    This function will RAISE if either env var is missing or the
    password is too short, to prevent silent misconfiguration.
    """
    if os.environ.get("CREATE_DEFAULT_ADMIN", "false").lower() != "true":
        print("CREATE_DEFAULT_ADMIN not set to 'true' — skipping default admin creation.")
        return

    password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "")
    if len(password) < 16:
        raise RuntimeError(
            "DEFAULT_ADMIN_PASSWORD must be at least 16 characters. "
            "Generate one with: openssl rand -hex 16"
        )

    db = SessionLocal()
    org_name = "Default Org"
    email = "admin@sentinel.ai"

    try:
        org = db.query(Organization).filter(Organization.name == org_name).first()
        if not org:
            org = Organization(name=org_name)
            db.add(org)
            db.commit()
            db.refresh(org)

        user = db.query(User).filter(User.email == email).first()
        if not user:
            new_user = User(
                email=email,
                hashed_password=get_password_hash(password),
                organization_id=org.id,
                role="admin"
            )
            db.add(new_user)
            db.commit()
            print(f"Created default admin: {email}")
        else:
            print("Default user already exists — skipping.")
    except Exception as e:
        print(f"Error creating default user: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    create_default()
