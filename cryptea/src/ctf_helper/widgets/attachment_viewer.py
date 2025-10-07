"""
GTK Attachment Viewer Widget
Displays and manages challenge attachments with inline image previews
"""

import os
from pathlib import Path
from typing import Optional, Callable

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio, Gdk, GdkPixbuf

from ..manager.attachments import AttachmentManager


class AttachmentRow(Gtk.Box):
    """A single row displaying an attachment with preview and actions"""
    
    def __init__(self, attachment: dict, manager: AttachmentManager, 
                 on_delete: Optional[Callable] = None):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        self.attachment = attachment
        self.manager = manager
        self.on_delete_callback = on_delete
        
        self.set_margin_start(6)
        self.set_margin_end(6)
        self.set_margin_top(6)
        self.set_margin_bottom(6)
        
        # Add style class
        self.add_css_class("card")
        
        self._build_ui()
    
    def _build_ui(self):
        """Build the attachment row UI"""
        # Preview/Icon section (left)
        if self.manager.is_image(self.attachment):
            self._add_image_preview()
        else:
            self._add_file_icon()
        
        # Info section (center)
        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        info_box.set_hexpand(True)
        info_box.set_valign(Gtk.Align.CENTER)
        
        # Filename
        filename_label = Gtk.Label(label=self.attachment["file_name"])
        filename_label.set_xalign(0)
        filename_label.add_css_class("heading")
        filename_label.set_ellipsize(3)  # Pango.EllipsizeMode.END
        info_box.append(filename_label)
        
        # Metadata
        file_size = AttachmentManager.format_file_size(self.attachment.get("file_size", 0))
        file_type = self.attachment.get("file_type", "unknown")
        
        # Show short type name
        if "/" in file_type:
            file_type = file_type.split("/")[1]
        
        meta_label = Gtk.Label(label=f"{file_size} • {file_type}")
        meta_label.set_xalign(0)
        meta_label.add_css_class("dim-label")
        meta_label.add_css_class("caption")
        info_box.append(meta_label)
        
        self.append(info_box)
        
        # Actions section (right)
        actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        actions_box.set_valign(Gtk.Align.CENTER)
        
        # View button
        view_btn = Gtk.Button()
        view_btn.set_icon_name("document-open-symbolic")
        view_btn.set_tooltip_text("Open with default application")
        view_btn.add_css_class("flat")
        view_btn.connect("clicked", self._on_view_clicked)
        actions_box.append(view_btn)
        
        # Delete button
        delete_btn = Gtk.Button()
        delete_btn.set_icon_name("user-trash-symbolic")
        delete_btn.set_tooltip_text("Delete attachment")
        delete_btn.add_css_class("flat")
        delete_btn.add_css_class("destructive-action")
        delete_btn.connect("clicked", self._on_delete_clicked)
        actions_box.append(delete_btn)
        
        self.append(actions_box)
    
    def _add_image_preview(self):
        """Add image preview thumbnail"""
        try:
            file_path = self.attachment["file_path"]
            
            # Load and scale image
            pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(
                file_path,
                width=64,
                height=64,
                preserve_aspect_ratio=True
            )
            
            texture = Gdk.Texture.new_for_pixbuf(pixbuf)
            image = Gtk.Image.new_from_paintable(texture)
            image.set_size_request(64, 64)
            
            # Wrap in frame
            frame = Gtk.Frame()
            frame.set_child(image)
            frame.add_css_class("card")
            
            self.append(frame)
        except Exception as e:
            print(f"Failed to load image preview: {e}")
            self._add_file_icon()
    
    def _add_file_icon(self):
        """Add file type-specific icon"""
        file_name = self.attachment.get("file_name", "")
        file_type = self.attachment.get("file_type", "")
        extension = Path(file_name).suffix.lower()
        
        # Determine icon based on file extension and type
        icon_name = self._get_icon_for_file(extension, file_type)
        
        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(48)
        icon.add_css_class("dim-label")
        icon.set_margin_start(8)
        icon.set_margin_end(8)
        
        self.append(icon)
    
    def _get_icon_for_file(self, extension: str, mime_type: str) -> str:
        """Get appropriate icon name for file type"""
        
        # Programming languages
        if extension == '.py':
            return "text-x-python-symbolic"
        elif extension in ['.c', '.h']:
            return "text-x-c-symbolic"
        elif extension in ['.cpp', '.hpp', '.cc', '.cxx']:
            return "text-x-cpp-symbolic"
        elif extension in ['.js', '.ts', '.jsx', '.tsx']:
            return "text-x-javascript-symbolic"
        elif extension in ['.java', '.class', '.jar']:
            return "text-x-java-symbolic"
        elif extension in ['.sh', '.bash', '.zsh']:
            return "text-x-script-symbolic"
        elif extension in ['.php']:
            return "text-x-php-symbolic"
        elif extension in ['.go']:
            return "text-x-go-symbolic"
        elif extension in ['.rs']:
            return "text-x-rust-symbolic"
        elif extension in ['.rb']:
            return "text-x-ruby-symbolic"
        elif extension in ['.asm', '.s']:
            return "text-x-asm-symbolic"
        
        # Executables
        elif extension in ['.exe', '.dll', '.msi']:
            return "application-x-executable-symbolic"
        elif extension in ['.elf', '.bin', '.so', '.o', '.a']:
            return "application-x-executable-symbolic"
        
        # Archives
        elif extension in ['.zip', '.7z', '.rar']:
            return "package-x-generic-symbolic"
        elif extension in ['.tar', '.gz', '.bz2', '.xz', '.tgz', '.tar.gz', '.tar.bz2', '.tar.xz']:
            return "package-x-generic-symbolic"
        
        # Documents
        elif extension == '.pdf':
            return "x-office-document-symbolic"
        elif extension in ['.doc', '.docx', '.odt', '.rtf']:
            return "x-office-document-symbolic"
        elif extension in ['.txt', '.md', '.log']:
            return "text-x-generic-symbolic"
        elif extension in ['.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg']:
            return "text-x-generic-symbolic"
        elif extension in ['.xml', '.html', '.htm']:
            return "text-html-symbolic"
        elif extension in ['.csv', '.xls', '.xlsx', '.ods']:
            return "x-office-spreadsheet-symbolic"
        
        # Media (audio/video)
        elif extension in ['.wav', '.mp3', '.ogg', '.flac', '.m4a', '.aac']:
            return "audio-x-generic-symbolic"
        elif extension in ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm']:
            return "video-x-generic-symbolic"
        
        # Disk images and forensics
        elif extension in ['.iso', '.img']:
            return "media-optical-symbolic"
        elif extension in ['.vhd', '.vhdx', '.vmdk', '.vdi', '.qcow2', '.ova']:
            return "drive-harddisk-symbolic"
        elif extension in ['.dd', '.raw', '.dmp', '.mem', '.dump']:
            return "drive-harddisk-symbolic"
        elif extension in ['.E01', '.aff', '.aff4', '.001']:
            return "drive-harddisk-symbolic"
        
        # Network captures
        elif extension in ['.pcap', '.pcapng', '.cap']:
            return "network-wired-symbolic"
        
        # Images (fallback if not caught by is_image)
        elif extension in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.ico']:
            return "image-x-generic-symbolic"
        
        # Default
        else:
            return "text-x-generic-symbolic"
    
    def _on_view_clicked(self, button):
        """Handle view button click"""
        self.manager.open_attachment(self.attachment["id"])
    
    def _on_delete_clicked(self, button):
        """Handle delete button click"""
        # Show confirmation dialog
        dialog = Adw.MessageDialog.new(
            self.get_root(),
            "Delete Attachment?",
            f"Are you sure you want to delete '{self.attachment['file_name']}'?"
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        
        dialog.connect("response", self._on_dialog_response)
        dialog.present()
    
    def _on_dialog_response(self, dialog, response):
        """Handle confirmation dialog response"""
        if response == "delete":
            success = self.manager.delete_attachment(self.attachment["id"])
            if success and self.on_delete_callback:
                self.on_delete_callback()


class AttachmentViewer(Gtk.Box):
    """Widget for viewing and managing challenge attachments"""
    
    def __init__(self, challenge_id: Optional[int] = None, manager: Optional[AttachmentManager] = None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        self.challenge_id = challenge_id
        self.manager = manager or AttachmentManager()
        
        # Set minimum size for empty state visibility
        self.set_size_request(-1, 200)
        
        self._build_ui()
        if self.challenge_id is not None:
            self._load_attachments()
    
    def load_challenge(self, challenge_id: int):
        """Load attachments for a specific challenge"""
        self.challenge_id = challenge_id
        self._load_attachments()
    
    def _build_ui(self):
        """Build the main UI"""
        # Toolbar
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        toolbar.set_margin_start(12)
        toolbar.set_margin_end(12)
        toolbar.set_margin_top(12)
        toolbar.set_margin_bottom(12)
        
        # Title
        title = Gtk.Label(label="Attachments")
        title.add_css_class("title-4")
        title.set_xalign(0)
        title.set_hexpand(True)
        toolbar.append(title)
        
        # Folder button
        folder_btn = Gtk.Button()
        folder_btn.set_icon_name("folder-open-symbolic")
        folder_btn.set_tooltip_text("Open attachment folder")
        folder_btn.add_css_class("flat")
        folder_btn.connect("clicked", self._on_open_folder)
        toolbar.append(folder_btn)
        
        # Screenshot button
        screenshot_btn = Gtk.Button()
        screenshot_btn.set_icon_name("camera-photo-symbolic")
        screenshot_btn.set_tooltip_text("Take screenshot")
        screenshot_btn.connect("clicked", self._on_take_screenshot)
        toolbar.append(screenshot_btn)
        
        # Add file button
        add_btn = Gtk.Button()
        add_btn.set_icon_name("list-add-symbolic")
        add_btn.set_tooltip_text("Add attachment")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._on_add_attachment)
        toolbar.append(add_btn)
        
        self.append(toolbar)
        
        # Separator
        separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        self.append(separator)
        
        # Attachments list box (no scrolling - show all attachments)
        self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.list_box.set_margin_start(12)
        self.list_box.set_margin_end(12)
        self.list_box.set_margin_top(12)
        self.list_box.set_margin_bottom(12)
        
        self.append(self.list_box)
        
        # Empty state (shown when no attachments)
        self.empty_state = Adw.StatusPage()
        self.empty_state.set_icon_name("mail-attachment-symbolic")
        self.empty_state.set_title("No Attachments")
        self.empty_state.set_description("Add screenshots, PCAPs, or related files")
        self.empty_state.set_vexpand(True)
        self.empty_state.set_valign(Gtk.Align.CENTER)
        
        # We'll swap between list and empty state
        self.empty_state.set_visible(False)
    
    def _load_attachments(self):
        """Load and display attachments"""
        # Clear existing
        while True:
            child = self.list_box.get_first_child()
            if child is None:
                break
            self.list_box.remove(child)
        
        # Check if challenge_id is set
        if self.challenge_id is None:
            return
        
        # Load from database
        attachments = self.manager.list_attachments(self.challenge_id)
        
        if not attachments:
            # Show empty state
            if self.empty_state.get_parent() is None:
                # Replace list box with empty state
                self.list_box.set_visible(False)
                self.append(self.empty_state)
                self.empty_state.set_visible(True)
        else:
            # Show list
            if self.empty_state.get_parent() is not None:
                self.remove(self.empty_state)
            
            self.list_box.set_visible(True)
            
            # Add attachment rows
            for attachment in attachments:
                row = AttachmentRow(
                    attachment,
                    self.manager,
                    on_delete=self._load_attachments
                )
                self.list_box.append(row)
    
    def _on_add_attachment(self, button):
        """Handle add attachment button click"""
        dialog = Gtk.FileDialog()
        dialog.set_title("Add Attachment")
        
        # Create file filter for allowed types
        filters = Gio.ListStore.new(Gtk.FileFilter)
        
        # All allowed files
        all_filter = Gtk.FileFilter()
        all_filter.set_name("All Allowed Files")
        for ext in AttachmentManager.ALLOWED_EXTENSIONS:
            all_filter.add_pattern(f"*{ext}")
        filters.append(all_filter)
        
        # Images
        image_filter = Gtk.FileFilter()
        image_filter.set_name("Images")
        for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.tiff', '.ico']:
            image_filter.add_pattern(f"*{ext}")
        filters.append(image_filter)
        
        # Audio files
        audio_filter = Gtk.FileFilter()
        audio_filter.set_name("Audio Files")
        for ext in ['.wav', '.mp3', '.ogg', '.flac', '.m4a', '.aac']:
            audio_filter.add_pattern(f"*{ext}")
        filters.append(audio_filter)
        
        # Video files
        video_filter = Gtk.FileFilter()
        video_filter.set_name("Video Files")
        for ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm']:
            video_filter.add_pattern(f"*{ext}")
        filters.append(video_filter)
        
        # Executables
        exe_filter = Gtk.FileFilter()
        exe_filter.set_name("Executables")
        for ext in ['.exe', '.dll', '.so', '.elf', '.bin', '.out', '.app']:
            exe_filter.add_pattern(f"*{ext}")
        filters.append(exe_filter)
        
        # Disk images
        disk_filter = Gtk.FileFilter()
        disk_filter.set_name("Disk Images")
        for ext in ['.vhd', '.vhdx', '.vmdk', '.qcow2', '.vdi', '.dd', '.img', '.iso']:
            disk_filter.add_pattern(f"*{ext}")
        filters.append(disk_filter)
        
        # Memory dumps
        mem_filter = Gtk.FileFilter()
        mem_filter.set_name("Memory Dumps")
        for ext in ['.dmp', '.mem', '.core', '.dump']:
            mem_filter.add_pattern(f"*{ext}")
        filters.append(mem_filter)
        
        # Network captures
        pcap_filter = Gtk.FileFilter()
        pcap_filter.set_name("Network Captures")
        for ext in ['.pcap', '.pcapng', '.cap']:
            pcap_filter.add_pattern(f"*{ext}")
        filters.append(pcap_filter)
        
        # Archives
        archive_filter = Gtk.FileFilter()
        archive_filter.set_name("Archives")
        for ext in ['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar']:
            archive_filter.add_pattern(f"*{ext}")
        filters.append(archive_filter)
        
        # Source code
        source_filter = Gtk.FileFilter()
        source_filter.set_name("Source Code")
        for ext in ['.py', '.c', '.cpp', '.java', '.js', '.php', '.sh', '.go', '.rs', '.asm']:
            source_filter.add_pattern(f"*{ext}")
        filters.append(source_filter)
        
        # Documents
        doc_filter = Gtk.FileFilter()
        doc_filter.set_name("Documents")
        for ext in ['.pdf', '.doc', '.docx', '.txt', '.md', '.html', '.xml', '.json']:
            doc_filter.add_pattern(f"*{ext}")
        filters.append(doc_filter)
        
        dialog.set_filters(filters)
        dialog.set_default_filter(all_filter)
        
        # Open multiple file selection dialog
        dialog.open_multiple(self.get_root(), None, self._on_files_selected)
    
    def _on_files_selected(self, dialog, result):
        """Handle multiple file selection"""
        if self.challenge_id is None:
            return
            
        try:
            files = dialog.open_multiple_finish(result)
            if files:
                # Get list of Gio.File objects
                file_list = []
                for i in range(files.get_n_items()):
                    file_list.append(files.get_item(i))
                
                # Add each file
                added_count = 0
                failed_count = 0
                errors = []
                
                for file in file_list:
                    file_path = file.get_path()
                    try:
                        self.manager.add_attachment(self.challenge_id, file_path)
                        added_count += 1
                    except ValueError as e:
                        failed_count += 1
                        errors.append(f"{file.get_basename()}: {str(e)}")
                    except IOError as e:
                        failed_count += 1
                        errors.append(f"{file.get_basename()}: {str(e)}")
                
                # Reload attachments
                self._load_attachments()
                
                # Show result
                if added_count > 0 and failed_count == 0:
                    if added_count == 1:
                        self._show_toast("1 attachment added")
                    else:
                        self._show_toast(f"{added_count} attachments added")
                elif added_count > 0 and failed_count > 0:
                    self._show_toast(f"{added_count} added, {failed_count} failed")
                    if errors:
                        error_msg = "\n".join(errors[:5])  # Show first 5 errors
                        if len(errors) > 5:
                            error_msg += f"\n... and {len(errors) - 5} more"
                        self._show_error_dialog("Some Files Failed", error_msg)
                elif failed_count > 0:
                    error_msg = "\n".join(errors[:5])
                    if len(errors) > 5:
                        error_msg += f"\n... and {len(errors) - 5} more"
                    self._show_error_dialog("Failed to Add Files", error_msg)
                    
        except Exception as e:
            if "dismissed" not in str(e).lower():
                print(f"Error selecting files: {e}")
    
    def _on_take_screenshot(self, button):
        """Handle take screenshot button click"""
        if self.challenge_id is None:
            return
            
        # Show toast with instruction
        self._show_toast("Select area to capture...")
        
        # Take screenshot asynchronously
        GLib.idle_add(self._do_take_screenshot)
    
    def _do_take_screenshot(self):
        """Actually take the screenshot"""
        if self.challenge_id is None:
            return False
            
        try:
            result = self.manager.take_screenshot(self.challenge_id, interactive=True)
            if result:
                self._load_attachments()
                self._show_toast("Screenshot saved")
            else:
                self._show_toast("Screenshot cancelled")
        except Exception as e:
            self._show_error_dialog("Screenshot Failed", str(e))
        return False  # Don't repeat
    
    def _on_open_folder(self, button):
        """Open attachment folder in file manager"""
        if self.challenge_id is None:
            return
            
        self.manager.open_challenge_folder(self.challenge_id)
    
    def _show_toast(self, message: str):
        """Show a toast notification"""
        # Find the toast overlay (should be in parent hierarchy)
        widget = self.get_parent()
        while widget:
            if isinstance(widget, Adw.ToastOverlay):
                toast = Adw.Toast.new(message)
                toast.set_timeout(2)
                widget.add_toast(toast)
                return
            widget = widget.get_parent()
        
        # Fallback: just print
        print(f"Toast: {message}")
    
    def _show_error_dialog(self, title: str, message: str):
        """Show error dialog"""
        dialog = Adw.MessageDialog.new(self.get_root(), title, message)
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.present()
    
    def refresh(self):
        """Refresh the attachment list"""
        self._load_attachments()
