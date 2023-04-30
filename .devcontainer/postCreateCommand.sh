#!/bin/bash
echo "Setting up Poetry..."

# setup Poetry
cd /workspaces/sbom-workshop

poetry install --no-ansi -q -n

echo "Done!"
