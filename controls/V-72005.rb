control "xccdf_mil.disa.stig_rule_SV-86629r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the root account must be the only account having unrestricted access to the system."
  desc  "
    Vulnerability Discussion: If an account other than root also has a User Identifier (UID) of \"0\", it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of \"0\" afford an opportunity for potential intruders to guess a password for a privileged account.
    
    Documentable: false
    
  "
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^(?!root:)[^:]*:[^:]*:0/) }
  end
end
