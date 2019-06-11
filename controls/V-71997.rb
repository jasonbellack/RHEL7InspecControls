control "xccdf_mil.disa.stig_rule_SV-86621r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be a vendor supported release."
  desc  "
    Vulnerability Discussion: An operating system release is considered \"supported\" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.
    
    Documentable: false
    
  "
  impact 1.0
  describe os do
    it { should be_unix }
  end
  describe.one do
    describe package("redhat-release-client") do
      it { should be_installed }
    end
    describe package("redhat-release-client") do
      its("version") { should cmp(/^7.*$/) }
    end
    describe package("redhat-release-workstation") do
      it { should be_installed }
    end
    describe package("redhat-release-workstation") do
      its("version") { should cmp(/^7.*$/) }
    end
    describe package("redhat-release-server") do
      it { should be_installed }
    end
    describe package("redhat-release-server") do
      its("version") { should cmp(/^7.*$/) }
    end
    describe package("redhat-release-computenode") do
      it { should be_installed }
    end
    describe package("redhat-release-computenode") do
      its("version") { should cmp(/^7.*$/) }
    end
  end
  describe file("/etc/redhat-release") do
    its("content") { should match(/^Red Hat Enterprise Linux.*release\s+(\S+)\s+/) }
  end
  file("/etc/redhat-release").content.to_s.scan(/^Red Hat Enterprise Linux.*release\s+(\S+)\s+/).flatten.each do |entry|
    describe entry do
      it { should eq "7.6" }
    end
  end
end
