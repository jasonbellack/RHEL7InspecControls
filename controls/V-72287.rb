control "xccdf_mil.disa.stig_rule_SV-86911r2_rule" do
  title "The Red Hat Enterprise Linux operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address."
  desc  "
    Vulnerability Discussion: Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    ipv4_icmp_echo_ignore_broadcasts = file("/etc/sysctl.conf").content.to_s.scan(/^\s*net\.ipv4\.icmp_echo_ignore_broadcasts[\s]*=[\s]*(\d+)\s*$/).flatten
    describe ipv4_icmp_echo_ignore_broadcasts.reject { |x| x == "1" } do
      it { should be_empty }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.icmp_echo_ignore_broadcasts[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.icmp_echo_ignore_broadcasts[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net\.ipv4\.icmp_echo_ignore_broadcasts[\s]*=[\s]*(\d+)\s*$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should_not be_nil }
    its("value") { should eq 1 }
  end
end
