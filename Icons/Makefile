# Generate MacDNS icon assets from iconset folders
#
# Expected structure:
#   Icons/macdns-logo/icon.iconset/   → AppIcon + AppLogo (About screen)
#   Icons/macdns-firstrun/icon.iconset/ → FirstRunLogo (first-run window)
#   Icons/macdns-on/icon.iconset/     → StatusOn
#   Icons/macdns-off/icon.iconset/    → StatusOff
#   Icons/macdns-light/icon.iconset/  → MenuBarIcon (light mode)
#   Icons/macdns-dark/icon.iconset/   → MenuBarIcon (dark mode)

ASSETS_DIR := Assets.xcassets

LOGO_ICONSET := macdns-logo/icon.iconset
FIRSTRUN_ICONSET := macdns-firstrun/icon.iconset
ON_ICONSET := macdns-on/icon.iconset
OFF_ICONSET := macdns-off/icon.iconset
LIGHT_ICONSET := macdns-light/icon.iconset
DARK_ICONSET := macdns-dark/icon.iconset

# Every source image, not the directories holding them: editing a PNG in place
# leaves the directory mtime untouched, so a stale catalog could ship from an
# incremental workspace.
ICON_SOURCES := $(shell find $(LOGO_ICONSET) $(FIRSTRUN_ICONSET) $(ON_ICONSET) $(OFF_ICONSET) $(LIGHT_ICONSET) $(DARK_ICONSET) -name '*.png' 2>/dev/null)
ASSETS_STAMP := .assets.stamp

# A catalog deleted by hand must regenerate even though its stamp survived.
ifeq ($(wildcard $(ASSETS_DIR)),)
$(shell rm -f $(ASSETS_STAMP))
endif

.PHONY: all clean

all: $(ASSETS_STAMP)

$(ASSETS_STAMP): $(ICON_SOURCES) Makefile
	@echo "Generating MacDNS icon assets..."
	@echo "Assets directory: $(ASSETS_DIR)"
	@# Full regeneration: a removed or renamed source must not survive as a
	@# leftover file inside the catalog.
	@rm -rf $(ASSETS_DIR)
	@for iconset in $(LOGO_ICONSET) $(FIRSTRUN_ICONSET) $(ON_ICONSET) $(OFF_ICONSET) $(LIGHT_ICONSET) $(DARK_ICONSET); do \
		if [ ! -d "$$iconset" ]; then \
			echo "Error: iconset not found: $$iconset"; \
			exit 1; \
		fi; \
	done
	@mkdir -p $(ASSETS_DIR)/AppIcon.appiconset
	@mkdir -p $(ASSETS_DIR)/AppLogo.imageset
	@mkdir -p $(ASSETS_DIR)/FirstRunLogo.imageset
	@mkdir -p $(ASSETS_DIR)/MenuBarIcon.imageset
	@mkdir -p $(ASSETS_DIR)/StatusOn.imageset
	@mkdir -p $(ASSETS_DIR)/StatusOff.imageset
	@echo "Generating App Icon from macdns-logo..."
	@cp $(LOGO_ICONSET)/*.png $(ASSETS_DIR)/AppIcon.appiconset/
	@echo '{\n  "images" : [\n    { "filename" : "icon_16x16.png", "idiom" : "mac", "scale" : "1x", "size" : "16x16" },\n    { "filename" : "icon_16x16@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "16x16" },\n    { "filename" : "icon_32x32.png", "idiom" : "mac", "scale" : "1x", "size" : "32x32" },\n    { "filename" : "icon_32x32@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "32x32" },\n    { "filename" : "icon_128x128.png", "idiom" : "mac", "scale" : "1x", "size" : "128x128" },\n    { "filename" : "icon_128x128@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "128x128" },\n    { "filename" : "icon_256x256.png", "idiom" : "mac", "scale" : "1x", "size" : "256x256" },\n    { "filename" : "icon_256x256@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "256x256" },\n    { "filename" : "icon_512x512.png", "idiom" : "mac", "scale" : "1x", "size" : "512x512" },\n    { "filename" : "icon_512x512@2x.png", "idiom" : "mac", "scale" : "2x", "size" : "512x512" }\n  ],\n  "info" : { "author" : "xcode", "version" : 1 }\n}' > $(ASSETS_DIR)/AppIcon.appiconset/Contents.json
	@echo "Generating App Logo from macdns-logo..."
	@cp $(LOGO_ICONSET)/icon_128x128.png $(ASSETS_DIR)/AppLogo.imageset/logo.png
	@cp $(LOGO_ICONSET)/icon_256x256.png $(ASSETS_DIR)/AppLogo.imageset/logo@2x.png
	@echo '{\n  "images" : [\n    { "filename" : "logo.png", "idiom" : "mac", "scale" : "1x" },\n    { "filename" : "logo@2x.png", "idiom" : "mac", "scale" : "2x" }\n  ],\n  "info" : { "author" : "xcode", "version" : 1 }\n}' > $(ASSETS_DIR)/AppLogo.imageset/Contents.json
	@echo "Generating First-run Logo from macdns-firstrun..."
	@cp $(FIRSTRUN_ICONSET)/icon_128x128.png $(ASSETS_DIR)/FirstRunLogo.imageset/logo.png
	@cp $(FIRSTRUN_ICONSET)/icon_256x256.png $(ASSETS_DIR)/FirstRunLogo.imageset/logo@2x.png
	@echo '{\n  "images" : [\n    { "filename" : "logo.png", "idiom" : "mac", "scale" : "1x" },\n    { "filename" : "logo@2x.png", "idiom" : "mac", "scale" : "2x" }\n  ],\n  "info" : { "author" : "xcode", "version" : 1 }\n}' > $(ASSETS_DIR)/FirstRunLogo.imageset/Contents.json
	@echo "Generating Menu Bar Icon with light/dark mode support..."
	@cp $(LIGHT_ICONSET)/icon_16x16.png $(ASSETS_DIR)/MenuBarIcon.imageset/menubar_light.png
	@cp $(LIGHT_ICONSET)/icon_16x16@2x.png $(ASSETS_DIR)/MenuBarIcon.imageset/menubar_light@2x.png
	@cp $(LIGHT_ICONSET)/icon_32x32.png $(ASSETS_DIR)/MenuBarIcon.imageset/menubar_light@3x.png
	@cp $(DARK_ICONSET)/icon_16x16.png $(ASSETS_DIR)/MenuBarIcon.imageset/menubar_dark.png
	@cp $(DARK_ICONSET)/icon_16x16@2x.png $(ASSETS_DIR)/MenuBarIcon.imageset/menubar_dark@2x.png
	@cp $(DARK_ICONSET)/icon_32x32.png $(ASSETS_DIR)/MenuBarIcon.imageset/menubar_dark@3x.png
	@echo '{\n  "images" : [\n    { "appearances" : [ { "appearance" : "luminosity", "value" : "light" } ], "filename" : "menubar_light.png", "idiom" : "mac", "scale" : "1x" },\n    { "appearances" : [ { "appearance" : "luminosity", "value" : "light" } ], "filename" : "menubar_light@2x.png", "idiom" : "mac", "scale" : "2x" },\n    { "appearances" : [ { "appearance" : "luminosity", "value" : "light" } ], "filename" : "menubar_light@3x.png", "idiom" : "mac", "scale" : "3x" },\n    { "appearances" : [ { "appearance" : "luminosity", "value" : "dark" } ], "filename" : "menubar_dark.png", "idiom" : "mac", "scale" : "1x" },\n    { "appearances" : [ { "appearance" : "luminosity", "value" : "dark" } ], "filename" : "menubar_dark@2x.png", "idiom" : "mac", "scale" : "2x" },\n    { "appearances" : [ { "appearance" : "luminosity", "value" : "dark" } ], "filename" : "menubar_dark@3x.png", "idiom" : "mac", "scale" : "3x" },\n    { "filename" : "menubar_light.png", "idiom" : "mac", "scale" : "1x" },\n    { "filename" : "menubar_light@2x.png", "idiom" : "mac", "scale" : "2x" },\n    { "filename" : "menubar_light@3x.png", "idiom" : "mac", "scale" : "3x" }\n  ],\n  "info" : { "author" : "xcode", "version" : 1 }\n}' > $(ASSETS_DIR)/MenuBarIcon.imageset/Contents.json
	@echo "Generating Status On Icon from macdns-on..."
	@cp $(ON_ICONSET)/icon_128x128.png $(ASSETS_DIR)/StatusOn.imageset/status_on.png
	@cp $(ON_ICONSET)/icon_256x256.png $(ASSETS_DIR)/StatusOn.imageset/status_on@2x.png
	@echo '{\n  "images" : [\n    { "filename" : "status_on.png", "idiom" : "mac", "scale" : "1x" },\n    { "filename" : "status_on@2x.png", "idiom" : "mac", "scale" : "2x" }\n  ],\n  "info" : { "author" : "xcode", "version" : 1 }\n}' > $(ASSETS_DIR)/StatusOn.imageset/Contents.json
	@echo "Generating Status Off Icon from macdns-off..."
	@cp $(OFF_ICONSET)/icon_128x128.png $(ASSETS_DIR)/StatusOff.imageset/status_off.png
	@cp $(OFF_ICONSET)/icon_256x256.png $(ASSETS_DIR)/StatusOff.imageset/status_off@2x.png
	@echo '{\n  "images" : [\n    { "filename" : "status_off.png", "idiom" : "mac", "scale" : "1x" },\n    { "filename" : "status_off@2x.png", "idiom" : "mac", "scale" : "2x" }\n  ],\n  "info" : { "author" : "xcode", "version" : 1 }\n}' > $(ASSETS_DIR)/StatusOff.imageset/Contents.json
	@echo '{\n  "info" : { "author" : "xcode", "version" : 1 }\n}' > $(ASSETS_DIR)/Contents.json
	@touch $(ASSETS_STAMP)
	@echo "Done! Assets generated at: $(ASSETS_DIR)"

clean:
	@echo "Cleaning generated assets..."
	@rm -rf $(ASSETS_DIR) $(ASSETS_STAMP)
	@echo "Done!"
