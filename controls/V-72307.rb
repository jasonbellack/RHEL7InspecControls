control "xccdf_mil.disa.stig_rule_SV-86931r4_rule" do
  title "The Red Hat Enterprise Linux operating system must not have an X Windows display manager installed unless approved."
  desc  "
    Vulnerability Discussion: Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented.
    
    Documentable: false
    
  "
  impact 0.5
  describe package("xorg-x11-server-common") do
    it { should_not be_installed }
  end
end
