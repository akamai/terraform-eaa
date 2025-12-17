# RDP Configuration Parameters

Configure Remote Desktop Protocol settings for RDP applications.

* `rdp_audio_redirection` - (Optional) Enable RDP audio redirection
* `rdp_clipboard_redirection` - (Optional) Enable RDP clipboard redirection
* `rdp_disk_redirection` - (Optional) Enable RDP disk redirection
* `rdp_printer_redirection` - (Optional) Enable RDP printer redirection
* `rdp_initial_program` - (Optional) RDP initial program
* `rdp_tls1` - (Optional) Enable RDP TLS 1.0
* `remote_spark_recording` - (Optional) Enable remote Spark recording
* `remote_spark_printer` - (Optional) Enable remote Spark printer
* `remote_spark_disk` - (Optional) Enable remote Spark disk
* `rdp_keyboard_lang` - (Optional) RDP keyboard language
* `rdp_remote_apps` - (Optional) RDP remote applications

## Example (RDP)
```json
{
  "rdp_audio_redirection": "true",
  "rdp_clipboard_redirection": "true",
  "rdp_disk_redirection": "false",
  "rdp_printer_redirection": "false",
  "rdp_initial_program": "C:\\Windows\\System32\\mstsc.exe",
  "rdp_tls1": "false",
  "rdp_keyboard_lang": "en-US",
  "rdp_remote_apps": ["notepad", "calc"]
}
```
