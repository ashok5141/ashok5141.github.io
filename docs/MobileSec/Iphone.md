# Iphone Security
- Setting up the **Mac Environemt** environment below are the links [IOS Download](https://techrechard.com/download-macos-ventura-iso-for-virtualbox-and-vmware/)

- I thought initially `IOS` for all of the apple family, but their different names their devices.

| Device | OS |
|:- | :- |
| Iphone | iOS |
| Ipad | IpadOS |
| iWatch | WatchOS |
| Macbook | macOS |

##### IOS Operating System
- IOS is a mobile operating system that Apple Inc. has designed for its iPhones, Second most popular and widely used after android.
> The structure of the iOS operating system is Layered based. Its communication doesn't occur directly. The layers between the Application Layer and the Hardware layer will help with Communication. The lower level gives basic services on which all applications rely and the higher-level layers provide graphics and interface-related services. Most of the system interfaces comes with a special package called a framework.
- A framework is a directory containing dynamic shared libraries, such as .files, header files, images, and helper applications that support the library. Every layer has its associated frameworks useful for a developer.
![Architecture of IOS](https://media.geeksforgeeks.org/wp-content/uploads/20210216081624/ios-660x295.png)

- CORE OS
    - It supports 64 bit enables the application to run faster
    - All the IOS thechnologies are built under the lowest level layer i.e. Core OS layer. These technologies include:
        - Core Bluetooth Framework
        - External Accessories Framework
        - Accelerate Framework
        - Security Service Framework
        - Local Authorization Framework etc    
- CORE SERVICES
    - Some important frameworks are present in the Core Services layer which helps the iOS os to cure itself and provide better functionality. It is the 2nd lowest layer in the Architecture, below frameworks are present in this layer.
    - Address Book Framework: The Address Book Framework provides access to the contact details of the user.
    - Cloud Kit Framework: This framework provides a medium to transfer data between your app and iCloud.
    - Core Data Framework: It is the technology used to handle the data model of a Model View Controller app.
    - Core Foundation Framework: This framework offers data management and service features for iOS applications.
    - Core Location Framework: This framework helps in delivering location and heading information to the application.
    - Core Motion Framework: All the motion-based data on the device is accessed with the help of the Core Motion Framework.
    - Foundation Framework: Objective C covering too many of the features found in the Core Foundation framework.
    - HealthKit Framework: This framework handles the health-related information of the user.
    - HomeKit Framework: This framework is used for talking with and controlling connected devices with the users home.
    - Social Framework: It is simply an interface that will access users' social media accounts.
    - StoreKit Framework: It provides support for purchasing content and services from within iOS apps.
- MEDIA LAYER
    - This layer helps, Enable all graphics video, and audio technology of the system. This is the second layer in te architecture. The different framework of MEDIA layer are:
    - ULKit Graphics: This framework provides support for designing images and animating the view content.
    - Core Graphics Framework: This framework support 2D vector and image-based rendering and it is a native drawing engine for iOS.
    - Core Animation: This framework provides the optimum animation experience of the apps in iOS.
    - Media Player Framework: This framework supports the playing of the playlist. It enables the user to use their iTunes library.
    - AV Kit: This framework offers a number of easy-to-use interfaces for video presentation and recording, and even playback of audio and video.
    - Open AL: This framework is also an Industry Standard Technology for Audio provision.
    - Core Images: This framework offers advanced support for motionless images.
    - GL Kit: This framework manages advanced 2D and 3D rendering by hardware-accelerated interfaces.
- COCOA TOUCH (APPLICATION LAYER)
    - COCOA Touch is also known as the application layer which acts as an interface for the user to work with the iOS Operating system. It supports touch and motion events and many more features. The COCOA TOUCH layer provides the following frameworks :
    - EvenKit Framework: This framework shows a standard system interface using view controllers for viewing and changing events.
    - GameKit Framework: This framework even allows users to share game related data online via a Game Center.
    - MapKit Framework: This framework provides a scrollable map that may be inserted into the user interface of the app.
    - PushKit Framework: This framework provides for registration.