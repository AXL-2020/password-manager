#include "User.h"

auto g_user = std::make_unique<User>();

void User::getLoginCreds() {
    std::cout << "Login" << std::endl;
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);
}

const std::string& User::getUsername() const { return username; }
std::string& User::getPassword() { return password; }