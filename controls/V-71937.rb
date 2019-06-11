control "xccdf_mil.disa.stig_rule_SV-86561r3_rule" do
  title "The Red Hat Enterprise Linux operating system must not have accounts configured with blank or null passwords."
  desc  "
    Vulnerability Discussion: If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.
    
    Documentable: false
    
  "
  impact 1.0
  describe file("/etc/pam.d/system-auth") do
    its("content") { should_not match(/^[^#]*\s*nullok\s*/) }
  end
  describe file("/etc/pam.d/password-auth") do
    its("content") { should_not match(/^[^#]*\s*nullok\s*/) }
  end
end
