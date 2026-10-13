verify-archive:
	python3 -I -B verify_public_evidence.py --root . --manifest-sha256 0e1c927eb7214e36fe9b6883a5ca64a1044e5febb7c07e27f58dfc54eeb8c201

reproduce:
	@echo "Full implementation reproduction unavailable: Titan source is not released."
	@exit 1

verify-negative-controls:
	python3 -I -B negative_controls.py --package-root . --manifest-sha256 0e1c927eb7214e36fe9b6883a5ca64a1044e5febb7c07e27f58dfc54eeb8c201 --verifier-sha256 8f935389d1f7dd30f34ca772beb0fa6ece1821102b6e0e677196b632c5786604
