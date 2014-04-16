## Version 0.2.1 (16 April 2014)

- Fix a difference between TLSSettings and TLSSettingsSimple,
  where connection would override the connection hostname and port in
  the simple case, but leave the field as is with TLSSettings.
  TLSSettings can now be used properly as template, and will be
  correctly overriden at the identification level only.
