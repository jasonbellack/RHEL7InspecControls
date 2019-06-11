control "xccdf_mil.disa.stig_rule_SV-86579r3_rule" do
  title "The Red Hat Enterprise Linux operating system must not allow an unrestricted logon to the system."
  desc  "
    Vulnerability Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security.
    
    Documentable: false
    
  "
  impact 1.0
  only_if { package("gdm").installed? } 
  describe.one do
    describe package("gdm") do
      it { should be_installed }
    end
    describe file("/etc/gdm/custom.conf") do
      its("content") { should match(/^\[daemon\]\n(?!([^\n]*\n+)*\[[^\n\]][*]([^\n]*\n+)*TimedLoginEnable=)([^\n]*\n+)*TimedLoginEnable=/) }
    end
    describe file("/etc/gdm/custom.conf") do
      its("content") { should match(/^TimedLoginEnable=(.*)$/) }
    end
    file("/etc/gdm/custom.conf").content.to_s.scan(/^TimedLoginEnable=(.*)$/).flatten.each do |entry|
      describe entry do
        it { should match(/^[Ff]alse$/) }
      end
    end
  end
end
