#pragma once 
#ifndef ROUTINGTABLE_H
#define ROUTINGTABLE_H
#include "..\common.h"
#include "..\utils.h"


enum RouteType {
    STATIC, 
    DYNAMIC,
    MANUAL
};

struct Route {
    uint32_t dst_ip{};
    uint32_t next_hop_ip{};
    uint8_t prefix_length{};
    // std::optional<uint32_t> next_hop_ip;
    uint8_t  iface {};
    uint8_t  metric{}; 
    RouteType type = DYNAMIC;
    std::vector<char> flags{};
    uint16_t time = 180;

    Route() = default;

    Route(uint32_t tempIp, uint8_t tempPrefix, uint8_t tempIface){
        dst_ip = tempIp;
        prefix_length = tempPrefix;
        iface = tempIface;
    }
    Route(uint32_t tempIp, uint8_t tempPrefix, uint8_t tempIface, RouteType tempType){
        dst_ip          = tempIp;
        prefix_length   = tempPrefix;
        iface = tempIface;
        type            = tempType;
    }
    Route(uint32_t tempIp, uint8_t tempPrefix, uint8_t tempIface, RouteType tempType, uint32_t tempNextHopIp){
        dst_ip          = tempIp;
        prefix_length   = tempPrefix;
        iface = tempIface;
        type            = tempType;
        flags.push_back('G');
        next_hop_ip     = tempNextHopIp;
    }
    Route(uint32_t tempIp, uint8_t tempPrefix, uint8_t tempIface, uint16_t tempTime){
        dst_ip          = tempIp;
        prefix_length   = tempPrefix;
        iface       = tempIface;
        time            = tempTime;
    }
};

struct Node {
    size_t label {};
    bool canCompress{true};
    Route route;
    Node* leftptr {nullptr};
    Node* rightptr {nullptr};

    Node(){
        route.dst_ip = 0;
        route.prefix_length = 0;
        route.iface = 0;
    }

    Node(Route tempRoute){
        label = generateRandomNumber(16);
        route = tempRoute;
    }
    // Node(Route tempRoute){
    //     label = generateRandomNumber(16);
    //     // route = tempRoute;
    //     route.dst_ip          = tempRoute.dst_ip;
    //     route.prefix_length   = tempRoute.prefix_length;
    //     route.iface       = tempRoute.iface;
    //     route.type            = tempRoute.type;
    // }

    Node(uint32_t tempIp, uint8_t tempPrefix, uint8_t tempIface){
        label = generateRandomNumber(16);
        route.dst_ip = tempIp;
        route.prefix_length = tempPrefix;
        route.iface = tempIface;
    }
};

Node *CreateNode()
{
    Node *newNode = new Node();
    if (!newNode)
    {
        spdlog::error("Memory error");
        return NULL;
    }
    return newNode;
}

Node *CreateNode(uint32_t tempIp, uint8_t tempPrefix, uint8_t tempIface)
{
    Node *newNode = new Node(tempIp, tempPrefix, tempIface);
    if (!newNode)
    {
        spdlog::error("Memory error");
        return NULL;
    }
    return newNode;
}

void CreateTable(Node *root, std::vector<Node> routing_table)
{
    std::vector<Node>::iterator ptr;

    int size = 32 - 1;
    // std::cout << "Size: " << size << std::endl;
    Node *tempRoot = root;

    for (ptr = routing_table.begin(); ptr < routing_table.end(); ptr++)
    {
        Route route = ptr->route;
        std::bitset<32> tempIp = route.dst_ip;
        tempRoot = root;
        for (size_t i{}; i < route.prefix_length; i++)
        {

            if (tempIp[size - i] == 0)
            {
                if (tempRoot->leftptr == nullptr)
                {
                    tempRoot->leftptr = CreateNode();
                }
                tempRoot = tempRoot->leftptr;
            }
            else
            {
                if (tempRoot->rightptr == nullptr)
                {
                    tempRoot->rightptr = CreateNode();
                }
                tempRoot = tempRoot->rightptr;
            }
        }
        if (tempRoot != nullptr) {

        tempRoot->label = ptr->label;
        tempRoot->route.dst_ip = ptr->route.dst_ip;
        tempRoot->route.iface = ptr->route.iface;
        tempRoot->route.prefix_length = ptr->route.prefix_length;
        }
    }
}

class RoutingTable {
public:

    RoutingTable(){
        CreateTable(root,routing_table);
        this->start(); // Calling the decrementing thread which decrements each entries lease time each second 
    } 
    RoutingTable(std::vector<Node> table){
        routing_table = table;
        CreateTable(root,routing_table);
        this->start(); // Calling the decrementing thread which decrements each entries lease time each second 
    } 
    
    // Just making sure that the thread doesnt run anymore
    // And destorying the entire table when done
    ~RoutingTable() {
    stop_thread = true;
    if (time_thread.joinable()) {
        time_thread.join();
    }
    DestroyTable();
    if (root != NULL) {
        root = nullptr;
        delete root;
    }
} 

    void InsertRoute(Node node){
        std::lock_guard<std::mutex> lock(muxTree);
        Node *tempRoot = root;
        int size = 32 - 1;
        Route route = node.route;
        std::bitset<32> tempIp = route.dst_ip;

        for (size_t i{}; i < route.prefix_length; i++)
            {

                if (tempIp[size - i] == 0)
                {
                    if (tempRoot->leftptr == nullptr)
                    {
                        tempRoot->leftptr = CreateNode();
                    }
                    tempRoot = tempRoot->leftptr;
                }
                else
                {
                    if (tempRoot->rightptr == nullptr)
                    {
                        tempRoot->rightptr = CreateNode();
                    }
                    tempRoot = tempRoot->rightptr;
                }
            }
            tempRoot->label = node.label;
            tempRoot->route.dst_ip = node.route.dst_ip;
            tempRoot->route.iface = node.route.iface;
            tempRoot->route.prefix_length = node.route.prefix_length;
            routing_table.push_back(node);
    }

    void DisplayTree()
    {   
        std::lock_guard<std::mutex> lock(muxTable);
        Node *tempRoot = root;

        // std::cout<<"DISPLAY!!! "<<ipToString(root->route.dst_ip)<<"\n";
        std::cout <<std::setw(16)<< "IP" << std::setw(7) << "Label"
        << ' ' << std::setw(7) << "Iface" << ' ' << std::setw(7) << "PLength" << ' ' << std::setw(7) << std::endl;
        recursiveDisplayTree(tempRoot);
    }

    void getRouteInfo( uint32_t ip, uint8_t *iface, uint32_t *next_hop_ip, std::vector<char> *flag, RouteType *type ) const {
        //const std::lock_guard<std::mutex> lock(muxTree);
        std::scoped_lock lock(muxTree);
        Node *tempRoot = root;
        short int size = 32 - 1;
        std::bitset<32> tempIp = ip;
        for (size_t i{}; i < size; i++)
        {
            if (!tempRoot)
            {
                return;
            }
            // Just need to check for iface not equal to 0 but just an extra check
            if (tempRoot->route.iface != 0 && 
                ((tempRoot->route.dst_ip&setMSBToOne(tempRoot->route.prefix_length)) == (ip&setMSBToOne(tempRoot->route.prefix_length))))
                *iface = tempRoot->route.iface;
                *next_hop_ip = tempRoot->route.next_hop_ip;
                flag->clear();
                for(char ch: tempRoot->route.flags){
                    flag->push_back(ch);
                }
                *type = tempRoot->route.type;
            if (tempIp[size - i] == 0)
            {
                tempRoot = tempRoot->leftptr;
            }
            else
            {
                tempRoot = tempRoot->rightptr;
            }
        }

        return;
    }

    void DestroyTable(){
        recursiveDestroyTable(root);
    }

    void RemoveRoute(Node &node){
        std::lock_guard<std::mutex> lock(muxTree);
        Node *tempRoot = root;
        int size = 32 - 1;
        Route route = node.route;
        std::bitset<32> tempIp = route.dst_ip;
        for (size_t i{}; i < route.prefix_length; i++)
            {
                // std::cout << "Iter: "<<+i<<std::endl;
                if(root==nullptr){
                    // std::cout << "HEHE\n";
                    root = tempRoot;
                    tempRoot = nullptr;
                    delete tempRoot;
                    return;
                }
                if (tempIp[size - i] == 0)
                {
                    // std::cout << "L\n";
                    root = root->leftptr;
                }
                else
                {
                    // std::cout << "R\n";
                    root = root->rightptr;
                }
                
            }
            if(root->label == node.label){
                root->label = 0;
                root->route.dst_ip = 0;
                root->route.iface = 0;
                root->route.prefix_length = 0;
            }
            root = tempRoot;
            tempRoot = nullptr;
            delete tempRoot;
    }

   // Start the decrementing thread
    void start() {
        time_thread = std::thread([this]() {
            size_t count{0};
            while (!stop_thread) {
                {   
                    // std::cout<<"TIME: "<<+count<<std::endl;
                    // Decrease the time for each entry
                    for (Node &entry : routing_table) {
                        --entry.route.time;
                    }

                    {   // Remove the entry 
                        std::lock_guard<std::mutex> lock(muxTable);
                        
                        // Use a temporary container to store the iterators of elements to be removed
                        std::vector<std::vector<Node>::iterator> to_remove;

                        // for (auto i = routing_table.begin(); i != routing_table.end(); ++i) {
                        //     if (i->route.time <= 0) {
                        //         std::cout << "Removed: " << ipToString(i->route.dst_ip) << " " << std::format("{:b}", ipToUint32(ipToString(i->route.dst_ip))) << std::endl;
                        //         RemoveRoute(*i);
                        //         to_remove.push_back(i);
                        //     }
                        // }
                        // std::cout<<"===================="<<"\n";

                        // // Erase elements outside of the loop to avoid iterator invalidation issues
                        // while (!to_remove.empty()) {
                        //     std::vector<Node>::iterator it = to_remove.back();
                        //     to_remove.pop_back();
                        //     routing_table.erase(it);
                        // }

                        auto i = routing_table.begin();
                        while (i != routing_table.end()) {
                            if (i->route.time <= 0) {
                                std::cout << "Removed: " << ipToString(i->route.dst_ip) << std::endl;
                                RemoveRoute(*i);
                                i = routing_table.erase(i);
                            } else {
                                ++i;
                            }
                        }
                        // std::cout<<"===================="<<"\n";

                        // for(auto el: routing_table){
                        //     std::cout<<"IP: "<<ipToString(el.route.dst_ip)<<"\n";
                        // }

                    } // Release the lock when lock goes out of scope
                }
                // Sleep after processing inside the while loop
                std::this_thread::sleep_for(std::chrono::seconds(1));
                count++;
            }
        });

        time_thread.detach();
    }

        // {{ipToUint32("192.168.0.0"), 17, 1,         STATIC, ipToUint32("192.168.10.0")}},
        // {{ipToUint32("192.170.0.0"), 17, 2,         STATIC, ipToUint32("192.170.10.0")}},
    Node* root = CreateNode(0, 32, 0);
    std::vector<Node> routing_table {
        {{ipToUint32("192.168.0.0"), 17, 1,         STATIC}},
        {{ipToUint32("192.170.0.0"), 17, 2,         STATIC}},
        {{ipToUint32("57.27.63.224"), 8, 1,         STATIC}},
        {{ipToUint32("28.119.253.94"), 8, 2,        STATIC}},
        {{ipToUint32("79.208.174.59"), 8, 3,        STATIC}},
        {{ipToUint32("95.197.245.125"), 8, 17,      STATIC}},
        {{ipToUint32("159.117.3.228"), 16, 15,      STATIC}},
        {{ipToUint32("210.27.223.214"), 24, 24,     STATIC}},
        {{ipToUint32("26.111.106.197"), 8, 27,      STATIC}},
        {{ipToUint32("67.171.230.220"), 8, 4,       STATIC}},
        {{ipToUint32("243.81.181.183"), 24, 11,     STATIC}},
        {{ipToUint32("114.62.94.160"), 8, 68,       STATIC}},
        {{ipToUint32("196.145.145.253"), 24, 75,    STATIC}},
        {{ipToUint32("227.179.117.85"), 24, 44,     STATIC}},
        {{ipToUint32("77.136.135.67"), 8, 33,       STATIC}},
        {{ipToUint32("18.176.229.2"), 8, 99,        STATIC}},
        {{ipToUint32("128.13.104.153"), 16, 99,     STATIC}},
        };

private:
    void recursiveDisplayTree(Node *node){
        if (node == NULL)
            return;
        std::cout <<std::setw(16)<< ipToString(node->route.dst_ip) << std::setw(7) << std::to_string(node->label)
        << ' ' << std::setw(7) << std::to_string(node->route.iface) << ' ' << std::setw(7) << std::to_string(node->route.prefix_length) << ' ' << std::setw(7) << std::endl;
        recursiveDisplayTree(node->leftptr);
        recursiveDisplayTree(node->rightptr);
    }

    void recursiveDestroyTable(Node *node){
        if (node == nullptr) {
            return;
        }
        recursiveDestroyTable(node->leftptr);
        recursiveDestroyTable(node->rightptr);
        delete node;
    }

    bool stop_thread = false;
    std::thread time_thread;
	mutable std::mutex muxTable;
	mutable std::mutex muxTree;

    // TODO: Need to make a clean tree function which would delete route and make the tree clean
};
#endif