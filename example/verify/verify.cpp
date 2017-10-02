//
// Copyright (c) 2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/ssl_verify
//

#include <boost/net/ssl_verify_callback.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/rfc2818_verification.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <iostream>

using tcp = boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

int main(int argc, char** argv)
{
    try
    {
        // Check command line arguments.
        if(argc != 2)
        {
            std::cerr <<
                "Usage: verify <host>\n" <<
                "Example:\n" <<
                "    verify www.example.com\n";
            return EXIT_FAILURE;
        }
        auto const host = argv[1];

        // The io_service is required for all I/O
        boost::asio::io_service ios;

        // The SSL context is required, and holds certificates
        ssl::context ctx{ssl::context::sslv23};
        ctx.set_verify_mode(ssl::verify_peer);

        // These objects perform our I/O
        tcp::resolver resolver{ios};
        ssl::stream<tcp::socket> stream{ios, ctx};

        // Look up the domain name
        auto const lookup = resolver.resolve({host, "https"});

        // Make the connection on the IP address we get from a lookup
        boost::asio::connect(stream.next_layer(), lookup);

        // Perform the SSL handshake
        stream.set_verify_callback(boost::net::ssl_verify_callback{host});
        stream.handshake(ssl::stream_base::client);

        // Gracefully close the stream
        boost::system::error_code ec;
        stream.shutdown(ec);
        if(ec == boost::asio::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec.assign(0, ec.category());
        }
        if(ec)
            throw boost::system::system_error{ec};

        // If we get here then the connection is closed gracefully
    }
    catch(std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}