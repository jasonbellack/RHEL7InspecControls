control "xccdf_mil.disa.stig_rule_SV-95715r1_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords."
  desc  "
    Vulnerability Discussion: Pluggable authentication modules (PAM) allow for a modular approach to integrating authentication methods. PAM operates in a top-down processing model and if the modules are not listed in the correct order, an important security function could be bypassed if stack entries are not centralized.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/passwd") do
    its("content") { should match(/^[\s]*password[ \t]+substack[ \t]+system-auth\s*$/) }
  end
end
