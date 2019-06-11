control "xccdf_mil.disa.stig_rule_SV-86577r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not allow an unattended or automatic logon to the system via a graphical user interface."
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
      its("content") { should match(/^\[daemon\]\n(?!([^\n]*\n+)*\[[^\n\]][*]([^\n]*\n+)*AutomaticLoginEnable=)([^\n]*\n+)*AutomaticLoginEnable=/) }
    end
    describe file("/etc/gdm/custom.conf") do
      its("content") { should match(/^AutomaticLoginEnable=(.*)$/) }
    end
    file("/etc/gdm/custom.conf").content.to_s.scan(/^AutomaticLoginEnable=(.*)$/).flatten.each do |entry|
      describe entry do
        it { should match(/^[Ff]alse$/) }
      end
    end
  end
end
