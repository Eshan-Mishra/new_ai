import React from 'react';
import { Github, Linkedin, Twitter } from 'lucide-react';

const Footer = () => {
  return (
    <footer className="bg-gray-900 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <h3 className="text-xl font-bold mb-4">AI Academy</h3>
            <p className="text-gray-400">
              Empowering the next generation of AI developers through comprehensive
              education and hands-on experience.
            </p>
          </div>
          <div>
            <h3 className="text-xl font-bold mb-4">Community Partners</h3>
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <img
                  src="https://developers.google.com/site-assets/images/home/google-developers-logo.png"
                  alt="Google Developer Group"
                  className="h-6"
                />
                <span>Google Developer Group</span>
              </div>
              <div className="flex items-center space-x-2">
                <img
                  src="https://d1.awsstatic.com/logos/aws-logo-lockups/poweredbyaws/PB_AWS_logo_RGB_stacked_REV_SQ.91cd4af40773cbfbd15577a3c2b8a346fe3e8fa2.png"
                  alt="AWS Community"
                  className="h-6"
                />
                <span>AWS Community Vadodara</span>
              </div>
            </div>
          </div>
          <div>
            <h3 className="text-xl font-bold mb-4">Connect With Us</h3>
            <div className="flex space-x-4">
              <a href="#" className="hover:text-blue-400">
                <Twitter className="h-6 w-6" />
              </a>
              <a href="#" className="hover:text-blue-600">
                <Linkedin className="h-6 w-6" />
              </a>
              <a href="#" className="hover:text-gray-400">
                <Github className="h-6 w-6" />
              </a>
            </div>
          </div>
        </div>
        <div className="mt-8 pt-8 border-t border-gray-800 text-center text-gray-400">
          <p>&copy; {new Date().getFullYear()} AI Academy. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;