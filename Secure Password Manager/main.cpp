#include <iostream>
#include <string>
#include <Windows.h>
#include "User.h"
#include "db.h"
#include "crypt.h"
#include "CredentialManager.h"

int main() {
    SetConsoleTitleA("Secure Password Manager");

    auto user = std::make_unique<User>();
    
    user->getLoginCreds();

    auto db = std::make_unique<DB>(*user);

    while (true) {
        
        if (!db->userExists()) {
            std::cout << "Username does not exist, would you like to create a new account using the credentials provided? (y/n): ";
            auto input = user->getInput<char>();

            if (input == 'y' || input == 'Y') {
                db->registerUser();
                break;
            }
            else {
                std::cout << "Reenter username" << std::endl;
                user->getLoginCreds();
            }


        }
        else {
            db->login();
            break;
        }
        std::cout << "Invalid smthn" << std::endl;
    }

    system("cls");
    std::cout << "Welcome " << user->getUsername() << "!" << std::endl;
    std::cout << "1. Add new credential entry" << std::endl;
    std::cout << "2. Retrieve credential entry" << std::endl;
    std::cout << "3. Update credential entry" << std::endl;
    std::cout << "4. Delete credential entry" << std::endl;
    std::cout << "Press any other key to exit" << std::endl;
    
    auto credManager = std::make_unique<CredentialManager>(db->getSQLiteDB(), db->getUserId(), user->getPassword());
    sodium_memzero(&user->getPassword()[0], user->getPassword().size());
    auto menuChoice = user->getInput<int>();
    
    while (menuChoice >= 1 && menuChoice <= 4) {
        switch (menuChoice) {
        case 1: {
            std::cout << "Enter service: ";
            std::string service = user->getInput<std::string>();
            std::cout << "Enter password for service: ";
            std::string servicePass = user->getInput<std::string>();
            if (credManager->addCredential(service, servicePass))
                std::cout << "Credential added successfully." << std::endl;
            else
                std::cout << "Failed to add credential." << std::endl;
            break;
        }
        case 2: {
            std::cout << "Enter service to retrieve: ";
            std::string service = user->getInput<std::string>();
            std::string servicePass;
            if (credManager->getCredential(service, servicePass))
                std::cout << "Password for " << service << ": " << servicePass << std::endl;
            else
                std::cout << "Credential not found." << std::endl;
            break;
        }
        case 3: {
            std::cout << "Enter service to update: ";
            std::string service = user->getInput<std::string>();
            std::cout << "Enter new password for service: ";
            std::string newPass = user->getInput<std::string>();
            if (credManager->updateCredential(service, newPass))
                std::cout << "Credential updated successfully." << std::endl;
            else
                std::cout << "Failed to update credential." << std::endl;
            break;
        }
        case 4: {
            std::cout << "Enter service to delete: ";
            std::string service = user->getInput<std::string>();
            if (credManager->deleteCredential(service))
                std::cout << "Credential deleted successfully." << std::endl;
            else
                std::cout << "Failed to delete credential." << std::endl;
            break;
        }
        default:
            std::cout << "Exiting." << std::endl;
            return 0;
        }
        std::cin.get();
        system("cls");
        std::cout << "1. Add new credential entry" << std::endl;
        std::cout << "2. Retrieve credential entry" << std::endl;
        std::cout << "3. Update credential entry" << std::endl;
        std::cout << "4. Delete credential entry" << std::endl;
        std::cout << "Press any other key to exit" << std::endl;
        menuChoice = user->getInput<int>();
    }
}