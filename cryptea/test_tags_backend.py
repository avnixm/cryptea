#!/usr/bin/env python3
"""
Test script for tags and template functionality
"""
import sys
from pathlib import Path
from ctf_helper.db import Database
from ctf_helper.manager.challenge_manager import ChallengeManager
from ctf_helper.manager.templates import TemplateManager
from ctf_helper.data_paths import user_data_dir

def test_database_migration():
    """Test that database has been migrated to v4 with tags column"""
    print("=" * 60)
    print("TEST 1: Database Migration")
    print("=" * 60)
    
    db = Database()
    
    # Check if tags column exists
    with db.cursor() as cur:
        cur.execute("PRAGMA table_info(challenges)")
        columns = [row[1] for row in cur.fetchall()]
        print(f"✓ Database columns: {columns}")
        if "tags" in columns:
            print(f"✓ Tags column exists in challenges table")
        else:
            print("✗ ERROR: Tags column not found!")
            return False
    
    print(f"✓ Database migration successful\n")
    return True

def test_challenge_with_tags():
    """Test creating and updating challenges with tags"""
    print("=" * 60)
    print("TEST 2: Challenge Creation with Tags")
    print("=" * 60)
    
    db = Database()
    manager = ChallengeManager(db)
    
    # Create a challenge with tags
    challenge = manager.create_challenge(
        title="Test Challenge with Tags",
        project="Test Project",
        category="Web",
        difficulty="medium",
        description="Testing tags functionality",
        tags=["sqli", "web", "database", "authentication"]
    )
    
    print(f"✓ Created challenge ID: {challenge.id}")
    print(f"✓ Challenge title: {challenge.title}")
    print(f"✓ Challenge tags: {challenge.tags}")
    
    if challenge.tags != ["sqli", "web", "database", "authentication"]:
        print("✗ ERROR: Tags don't match expected values!")
        return False
    
    # Retrieve the challenge and verify tags persist
    retrieved = manager.get_challenge(challenge.id)
    print(f"✓ Retrieved challenge tags: {retrieved.tags}")
    
    if retrieved.tags != challenge.tags:
        print("✗ ERROR: Retrieved tags don't match!")
        return False
    
    # Update tags
    updated = manager.update_challenge(
        challenge.id,
        tags=["sqli", "web", "updated"]
    )
    print(f"✓ Updated challenge tags: {updated.tags}")
    
    if updated.tags != ["sqli", "web", "updated"]:
        print("✗ ERROR: Updated tags don't match!")
        return False
    
    # Clean up
    manager.delete_challenge(challenge.id)
    print("✓ Test challenge deleted")
    print("✓ Challenge tags test passed\n")
    return True

def test_tag_filtering():
    """Test filtering challenges by tags"""
    print("=" * 60)
    print("TEST 3: Tag Filtering")
    print("=" * 60)
    
    db = Database()
    manager = ChallengeManager(db)
    
    # Create test challenges with different tags
    c1 = manager.create_challenge(
        title="Web SQLi Challenge",
        project="Test",
        category="Web",
        tags=["sqli", "web", "database"]
    )
    
    c2 = manager.create_challenge(
        title="Crypto RSA Challenge",
        project="Test",
        category="Crypto",
        tags=["rsa", "crypto", "math"]
    )
    
    c3 = manager.create_challenge(
        title="Web XSS Challenge",
        project="Test",
        category="Web",
        tags=["xss", "web", "javascript"]
    )
    
    print(f"✓ Created 3 test challenges")
    
    # Filter by single tag
    web_challenges = manager.list_challenges(tags=["web"])
    print(f"✓ Challenges with 'web' tag: {len(web_challenges)}")
    
    if len(web_challenges) != 2:
        print(f"✗ ERROR: Expected 2 web challenges, got {len(web_challenges)}")
        manager.delete_challenge(c1.id)
        manager.delete_challenge(c2.id)
        manager.delete_challenge(c3.id)
        return False
    
    # Filter by multiple tags (AND logic)
    sqli_challenges = manager.list_challenges(tags=["web", "sqli"])
    print(f"✓ Challenges with 'web' AND 'sqli' tags: {len(sqli_challenges)}")
    
    if len(sqli_challenges) != 1:
        print(f"✗ ERROR: Expected 1 sqli challenge, got {len(sqli_challenges)}")
        manager.delete_challenge(c1.id)
        manager.delete_challenge(c2.id)
        manager.delete_challenge(c3.id)
        return False
    
    # Search should also find tags
    search_results = manager.list_challenges(search="rsa")
    print(f"✓ Search for 'rsa': {len(search_results)} results")
    
    if len(search_results) < 1:
        print("✗ ERROR: Search should find challenges by tags!")
        manager.delete_challenge(c1.id)
        manager.delete_challenge(c2.id)
        manager.delete_challenge(c3.id)
        return False
    
    # Clean up
    manager.delete_challenge(c1.id)
    manager.delete_challenge(c2.id)
    manager.delete_challenge(c3.id)
    print("✓ Test challenges deleted")
    print("✓ Tag filtering test passed\n")
    return True

def test_template_manager():
    """Test template loading and listing"""
    print("=" * 60)
    print("TEST 4: Template Manager")
    print("=" * 60)
    
    template_mgr = TemplateManager()
    
    # List templates
    templates = template_mgr.list_templates()
    print(f"✓ Found {len(templates)} templates:")
    
    for tmpl in templates:
        print(f"  - {tmpl.title} ({tmpl.category}, {tmpl.difficulty})")
        print(f"    Tags: {', '.join(tmpl.tags)}")
    
    if len(templates) == 0:
        print("✗ ERROR: No templates found!")
        return False
    
    # Load a specific template
    if templates:
        first_template = templates[0]
        loaded = template_mgr.get_template(first_template.filename)
        print(f"\n✓ Loaded template: {loaded.title}")
        print(f"  Category: {loaded.category}")
        print(f"  Difficulty: {loaded.difficulty}")
        print(f"  Tags: {loaded.tags}")
        print(f"  Description length: {len(loaded.description)} chars")
        
        if not loaded.title or not loaded.description:
            print("✗ ERROR: Template missing required fields!")
            return False
    
    print("✓ Template manager test passed\n")
    return True

def test_export_import_with_tags():
    """Test exporting and importing challenges with tags"""
    print("=" * 60)
    print("TEST 5: Export/Import with Tags")
    print("=" * 60)
    
    db = Database()
    manager = ChallengeManager(db)
    
    # Create a challenge with tags
    original = manager.create_challenge(
        title="Export Test Challenge",
        project="Export Test",
        category="Misc",
        description="Testing export with tags",
        tags=["export", "test", "tags"]
    )
    print(f"✓ Created challenge with tags: {original.tags}")
    
    # Export
    exported = manager.export_all()
    export_item = None
    for item in exported:
        if item["title"] == "Export Test Challenge":
            export_item = item
            break
    
    if not export_item:
        print("✗ ERROR: Could not find exported challenge!")
        manager.delete_challenge(original.id)
        return False
    
    print(f"✓ Exported challenge has tags: {export_item.get('tags', [])}")
    
    if export_item.get("tags") != ["export", "test", "tags"]:
        print("✗ ERROR: Exported tags don't match!")
        manager.delete_challenge(original.id)
        return False
    
    # Delete original
    manager.delete_challenge(original.id)
    
    # Import back
    imported = manager.import_from([export_item])
    print(f"✓ Imported {len(imported)} challenge(s)")
    
    if len(imported) != 1:
        print("✗ ERROR: Import failed!")
        return False
    
    imported_challenge = imported[0]
    print(f"✓ Imported challenge tags: {imported_challenge.tags}")
    
    if imported_challenge.tags != ["export", "test", "tags"]:
        print("✗ ERROR: Imported tags don't match!")
        manager.delete_challenge(imported_challenge.id)
        return False
    
    # Clean up
    manager.delete_challenge(imported_challenge.id)
    print("✓ Test challenge deleted")
    print("✓ Export/import test passed\n")
    return True

def main():
    print("\n" + "=" * 60)
    print("CRYPTEA TAGS & TEMPLATES BACKEND TEST SUITE")
    print("=" * 60 + "\n")
    
    tests = [
        test_database_migration,
        test_challenge_with_tags,
        test_tag_filtering,
        test_template_manager,
        test_export_import_with_tags,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"✗ TEST FAILED WITH EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✓ ALL TESTS PASSED!")
        return 0
    else:
        print(f"✗ {total - passed} TEST(S) FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
