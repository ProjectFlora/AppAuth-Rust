#!/usr/bin/env python3
import sys
import os
import re

def update_package_swift(version, app_checksum):
    package_file = "Package.swift"
    if not os.path.exists(package_file):
        print(f"Error: {package_file} not found.")
        sys.exit(1)

    with open(package_file, "r") as f:
        content = f.read()

    # Ensure version starts with 'v' for the URL part
    # But we might want to keep it as is for other parts if needed.
    # The current Package.swift uses v0.4.0 in the URL.
    url_version = version if version.startswith("v") else f"v{version}"

    # We want to find the binaryTarget block and update its url and checksum.
    # The structure is:
    #         .binaryTarget(
    #             name: "AppAuthRustBinary",
    #             url: "...",
    #             checksum: "..."
    #         ),
    
    # We'll use a regex to find the block of AppAuthRustBinary
    # and replace the url and checksum lines within it.
    
    # Pattern to find the binaryTarget block for "AppAuthRustBinary"
    # This regex looks for .binaryTarget( ... ) where name: "AppAuthRustBinary" is present
    pattern = r'\.binaryTarget\(\s*name: "AppAuthRustBinary",\s*url: ".*?",\s*checksum: ".*?"\s*\)'
    
    def replace_block(match):
        block = match.group(0)
        # Replace URL
        block = re.sub(r'url: ".*?",', f'url: "https://github.com/ProjectFlora/AppAuth-Rust/releases/download/{url_version}/AppAuthRust-Apple-{url_version}.zip",', block)
        # Replace Checksum
        block = re.sub(r'checksum: ".*?"', f'checksum: "{app_checksum}"', block)
        return block

    new_content = re.sub(pattern, replace_block, content, flags=re.DOTALL)

    with open(package_file, "w") as f:
        f.write(new_content)
    print(f"Successfully updated {package_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: update_package_swift.py <version> <checksum>")
        sys.exit(1)
    
    update_package_swift(sys.argv[1], sys.argv[2])
