import sys
import json
import os
from pathlib import Path
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                               QMessageBox, QFormLayout, QGroupBox, QFrame)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QFont, QPixmap, QPainter, QColor


class ModernButton(QPushButton):
    def __init__(self, text, color="#2196F3"):
        super().__init__(text)
        self.color = color
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 14px;
                min-width: 120px;
            }}
            QPushButton:hover {{
                background-color: {self._darken_color(color, 0.1)};
                transform: translateY(-1px);
            }}
            QPushButton:pressed {{
                background-color: {self._darken_color(color, 0.2)};
                transform: translateY(1px);
            }}
            QPushButton:disabled {{
                background-color: #cccccc;
                color: #666666;
            }}
        """)
    
    def _darken_color(self, hex_color, factor):
        color = QColor(hex_color)
        h, s, v, a = color.getHsv()
        v = max(0, int(v * (1 - factor)))
        color.setHsv(h, s, v, a)
        return color.name()


class ConfigEditor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config_file_path = "config.json"
        self.init_ui()
        self.load_existing_config()
        
    def init_ui(self):
        self.setWindowTitle("Config.json Editor")
        self.setGeometry(200, 200, 600, 450)
        self.setMinimumSize(500, 400)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(30, 30, 30, 30)
        
        # Header section
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        
        title_label = QLabel("⚙️ Configuration Editor")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
                background: transparent;
                padding: 0px;
            }
        """)
        title_label.setAlignment(Qt.AlignCenter)
        
        subtitle_label = QLabel("Manage your config.json settings")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: rgba(255, 255, 255, 0.8);
                font-size: 14px;
                background: transparent;
                padding: 0px;
            }
        """)
        subtitle_label.setAlignment(Qt.AlignCenter)
        
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        main_layout.addWidget(header_frame)
        
        # Status indicator
        self.status_label = QLabel("📁 config.json")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #2196F3;
                font-weight: 600;
                font-size: 14px;
                padding: 8px 12px;
                background-color: #E3F2FD;
                border-radius: 6px;
                border: 1px solid #BBDEFB;
            }
        """)
        main_layout.addWidget(self.status_label)
        
        # Configuration form
        config_group = QGroupBox()
        config_group.setStyleSheet("""
            QGroupBox {
                border: 2px solid #E0E0E0;
                border-radius: 12px;
                margin-top: 12px;
                padding-top: 20px;
                background-color: white;
            }
        """)
        
        form_layout = QFormLayout()
        form_layout.setSpacing(20)
        form_layout.setContentsMargins(30, 20, 30, 30)
        
        # User ID input
        user_id_label = QLabel("User ID:")
        user_id_label.setStyleSheet("""
            QLabel {
                color: #333333;
                font-weight: 600;
                font-size: 14px;
            }
        """)
        
        self.user_id_input = QLineEdit()
        self.user_id_input.setPlaceholderText("Enter numeric user ID (e.g., 2727)")
        self.user_id_input.setStyleSheet("""
            QLineEdit {
                padding: 12px 16px;
                border: 2px solid #E0E0E0;
                border-radius: 8px;
                font-size: 14px;
                background-color: #FAFAFA;
                min-height: 20px;
            }
            QLineEdit:focus {
                border-color: #2196F3;
                background-color: white;
            }
            QLineEdit:hover {
                border-color: #BDBDBD;
            }
        """)
        
        # Email input
        email_label = QLabel("Notification Email:")
        email_label.setStyleSheet("""
            QLabel {
                color: #333333;
                font-weight: 600;
                font-size: 14px;
            }
        """)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email address (e.g., user@example.com)")
        self.email_input.setStyleSheet("""
            QLineEdit {
                padding: 12px 16px;
                border: 2px solid #E0E0E0;
                border-radius: 8px;
                font-size: 14px;
                background-color: #FAFAFA;
                min-height: 20px;
            }
            QLineEdit:focus {
                border-color: #2196F3;
                background-color: white;
            }
            QLineEdit:hover {
                border-color: #BDBDBD;
            }
        """)
        
        form_layout.addRow(user_id_label, self.user_id_input)
        form_layout.addRow(email_label, self.email_input)
        
        config_group.setLayout(form_layout)
        main_layout.addWidget(config_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        self.save_button = ModernButton("💾 Save Config", "#4CAF50")
        self.save_button.clicked.connect(self.save_config)
        
        self.reload_button = ModernButton("🔄 Reload", "#FF9800")
        self.reload_button.clicked.connect(self.load_existing_config)
        
        self.clear_button = ModernButton("🗑️ Clear", "#F44336")
        self.clear_button.clicked.connect(self.clear_inputs)
        
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.reload_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addStretch()
        
        main_layout.addLayout(button_layout)
        main_layout.addStretch()
        
        # Apply main window styling
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
        """)
        
    def load_existing_config(self):
        """Load configuration from config.json if it exists"""
        try:
            if os.path.exists(self.config_file_path):
                with open(self.config_file_path, 'r') as file:
                    config_data = json.load(file)
                
                # Populate the form fields
                self.user_id_input.setText(str(config_data.get('user_id', '')))
                self.email_input.setText(config_data.get('notification_email', ''))
                
                self.update_status("✅ Loaded successfully", "#4CAF50")
                
            else:
                self.update_status("📝 New config.json", "#FF9800")
                
        except json.JSONDecodeError:
            self.update_status("❌ Invalid JSON format", "#F44336")
            QMessageBox.critical(self, "Error", "config.json contains invalid JSON format!")
        except Exception as e:
            self.update_status("❌ Load failed", "#F44336")
            QMessageBox.critical(self, "Error", f"Failed to load config.json: {str(e)}")
    
    def save_config(self):
        """Save configuration to config.json"""
        try:
            # Validate user ID
            user_id_text = self.user_id_input.text().strip()
            if not user_id_text:
                self.show_validation_error("User ID cannot be empty!")
                return
            
            try:
                user_id = int(user_id_text)
            except ValueError:
                self.show_validation_error("User ID must be a valid number!")
                return
            
            # Validate email
            email = self.email_input.text().strip()
            if not email:
                self.show_validation_error("Email cannot be empty!")
                return
            
            if '@' not in email or '.' not in email.split('@')[-1]:
                self.show_validation_error("Please enter a valid email address!")
                return
            
            # Create config data
            config_data = {
                "user_id": user_id,
                "notification_email": email
            }
            
            # Save to file with proper formatting
            with open(self.config_file_path, 'w') as file:
                json.dump(config_data, file, indent=4)
            
            self.update_status("💾 Saved successfully", "#4CAF50")
            self.show_success_message("Configuration saved to config.json!")
            
        except Exception as e:
            self.update_status("❌ Save failed", "#F44336")
            QMessageBox.critical(self, "Error", f"Failed to save config.json: {str(e)}")
    
    def clear_inputs(self):
        """Clear all input fields"""
        reply = QMessageBox.question(self, "Clear Fields", 
                                   "Are you sure you want to clear all fields?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.user_id_input.clear()
            self.email_input.clear()
            self.update_status("🗑️ Fields cleared", "#FF9800")
    
    def update_status(self, message, color):
        """Update status label with message and color"""
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {color};
                font-weight: 600;
                font-size: 14px;
                padding: 8px 12px;
                background-color: {color}20;
                border-radius: 6px;
                border: 1px solid {color}40;
            }}
        """)
    
    def show_validation_error(self, message):
        """Show validation error with custom styling"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Validation Error")
        msg_box.setText(message)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: white;
            }
            QMessageBox QLabel {
                color: #333333;
                font-size: 14px;
            }
        """)
        msg_box.exec()
    
    def show_success_message(self, message):
        """Show success message with custom styling"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setWindowTitle("Success")
        msg_box.setText(message)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: white;
            }
            QMessageBox QLabel {
                color: #333333;
                font-size: 14px;
            }
        """)
        msg_box.exec()


def main():
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Config.json Editor")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Professional Tools")
    
    # Set application style
    app.setStyle('Fusion')
    
    window = ConfigEditor()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
