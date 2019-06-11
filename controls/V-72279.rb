control "xccdf_mil.disa.stig_rule_SV-86903r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not contain shosts.equiv files."
  desc  "
    Vulnerability Discussion: The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.
    
    Documentable: false
    
  "
  impact 1.0
  describe command("find / -regex .\\*/shosts.equiv -type f  -xdev") do
    its("stdout") { should be_empty }
  end
end
