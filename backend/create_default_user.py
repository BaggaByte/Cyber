from database import SessionLocal
from models import User, Organization
from auth import get_password_hash

def create_default():
    db = SessionLocal()
    org_name = "Default Org"
    email = "admin@sentinel.ai"
    password = "admin"

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
            print(f"Created default user: {email} / {password}")
        else:
            print("Default user already exists.")
    except Exception as e:
        print(f"Error creating default user: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_default()
