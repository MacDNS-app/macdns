-- Lays out the mounted, writable DMG volume: background with the drag arrow,
-- 96pt icons placed on the arrow's ends. Finder saves it in the volume's .DS_Store.
-- Usage: osascript dmg-layout.applescript <mount point> <app bundle name>
on run argv
	set mountPoint to item 1 of argv
	set appName to item 2 of argv
	tell application "Finder"
		set dmgRoot to (POSIX file mountPoint) as alias
		open dmgRoot
		set dmgWindow to container window of dmgRoot
		set current view of dmgWindow to icon view
		set toolbar visible of dmgWindow to false
		set statusbar visible of dmgWindow to false
		set pathbar visible of dmgWindow to false
		-- Matches the 660x400 background. The title bar only crops its plain bottom edge.
		set bounds of dmgWindow to {200, 120, 860, 520}
		set viewOptions to icon view options of dmgWindow
		set arrangement of viewOptions to not arranged
		set icon size of viewOptions to 96
		set text size of viewOptions to 13
		set background picture of viewOptions to (POSIX file (mountPoint & "/.background/background.tiff") as alias)
		set position of item appName of dmgRoot to {165, 185}
		set position of item "Applications" of dmgRoot to {495, 185}
		-- Finder applies the background only after the window reopens.
		close dmgWindow
		open dmgRoot
		update dmgRoot without registering applications
		delay 2
		close container window of dmgRoot
		delay 1
	end tell
end run
