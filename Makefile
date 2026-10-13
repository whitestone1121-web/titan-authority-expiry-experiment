verify-archive:
	python3 -I -B verify_signed_approval_evidence.py . --manifest-sha256 4167c98c403e728deb97258e583832780f5b51f6cb7ff0207768ef9bd94eb630

verify-negative-controls:
	python3 -I -B negative_signed_approval_controls.py . --manifest-sha256 4167c98c403e728deb97258e583832780f5b51f6cb7ff0207768ef9bd94eb630 --verifier-sha256 69da325ed240dc2812440030e0dc4488b8309acf326ab5d421d6a3771a9f8506

reproduce:
	@echo "Full experiment reproduction unavailable: Titan implementation and private harness are not released."
	@exit 1
