control "xccdf_mil.disa.stig_rule_SV-86611r2_rule" do
  title "The Red Hat Enterprise Linux operating system must remove all software components after updated versions have been installed."
  desc  "
    Vulnerability Discussion: Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.
    
    Documentable: false
    
  "
  impact 0.1
  describe file("/etc/yum.conf") do
    its("content") { should match(/^\s*clean_requirements_on_remove\s*=\s*(\S+)\s*$/) }
  end
  file("/etc/yum.conf").content.to_s.scan(/^\s*clean_requirements_on_remove\s*=\s*(\S+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(1|True|yes)$/) }
    end
  end
end
