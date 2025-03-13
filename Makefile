.PHONY: tag

TAG_PREFIX=v
VERSION_FILE=VERSION

tag:
	@git fetch --tags
	@LATEST_TAG=$$(git tag --sort=-v:refname | head -n 1); \
	if [ -z "$$LATEST_TAG" ]; then \
		NEXT_VERSION="$(TAG_PREFIX)1.0.0"; \
	else \
		NEXT_VERSION=$$(echo $$LATEST_TAG | awk -F. -v OFS=. '{print $$1"."$$2"."$$3+1}'); \
	fi; \
	echo "Creating new tag: $$NEXT_VERSION"; \
	git tag $$NEXT_VERSION; \
	git push origin $$NEXT_VERSION

.PHONY: tf-validate tf-init tf-plan

tf-validate: | tf-init
	@terraform -chdir=src validate

tf-init: 
	@terraform -chdir=src init

tf-plan: | tf-validate
	@bash +x ./scripts/tf-plan.sh
	@echo "$$?"
