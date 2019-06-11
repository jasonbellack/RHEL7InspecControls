control "xccdf_mil.disa.stig_rule_SV-86915r4_rule" do
  title "The Red Hat Enterprise Linux operating system must not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default."
  desc  "
    Vulnerability Discussion: ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^[\s]*net\.ipv4\.conf\.default\.send_redirects[\s]*=[\s]*0[\s]*$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*net\.ipv4\.conf\.default\.send_redirects[\s]*=[\s]*0[\s]*$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*net\.ipv4\.conf\.default\.send_redirects[\s]*=[\s]*0[\s]*$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*net\.ipv4\.conf\.default\.send_redirects[\s]*=[\s]*0[\s]*$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should eq 0 }
  end
end
