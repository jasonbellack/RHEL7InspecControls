control "xccdf_mil.disa.stig_rule_SV-86909r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default."
  desc  "
    Vulnerability Discussion: Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    ipv4_accept_source_route = file("/etc/sysctl.conf").content.to_s.scan(/^\s*net\.ipv4\.conf\.default\.accept_source_route[\s]*=[\s]*(\d+)\s*$/).flatten
    describe ipv4_accept_source_route.reject { |x| x == "0" } do
      it { should be_empty }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.conf\.default\.accept_source_route[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.conf\.default\.accept_source_route[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.conf\.default\.accept_source_route[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should_not be_nil }
    its("value") { should eq 0 }
  end
end
