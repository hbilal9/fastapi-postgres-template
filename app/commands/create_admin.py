#!/usr/bin/env python3
"""
Usage: python -m app.commands.create_admin
"""

import sys
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def create_superuser():
    try:
        import uuid

        from sqlalchemy.orm import Session

        from app.models.user import User
        from app.utils.database import engine
        from app.utils.security import hash_password
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you're running this from the project root directory.")
        return

    ADMIN_DATA = {
        "first_name": "Admin",
        "last_name": "User",
        "email": "admin@gmail.com",
        "password": "password1",
    }

    print("🚀Create Superuser")
    print("=" * 50)

    db = Session(bind=engine)
    try:
        existing_admin = (
            db.query(User).filter(User.email == ADMIN_DATA["email"]).first()
        )

        if existing_admin:
            print("❌ Admin user already exists!")
            return

        print("Creating superuser with default credentials...")
        print("-" * 50)

        admin_user = User(
            id=uuid.uuid4(),
            first_name=ADMIN_DATA["first_name"],
            last_name=ADMIN_DATA["last_name"],
            email=ADMIN_DATA["email"],
            password_hash=hash_password(ADMIN_DATA["password"]),
            is_active=True,
        )

        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

        print("✅ Superuser created successfully!")
        print("\n🎉 You can now login to the system!")
        print("\n⚠️  IMPORTANT: Change the default password after first login!")

    except Exception as e:
        db.rollback()
        print(f"❌ Error creating superuser: {str(e)}")
        raise
    finally:
        db.close()


def main():
    try:
        create_superuser()
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
