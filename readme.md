## Gateway

This is a simple application designed to act as a gateway for apis.  

It was designed with a cloud foundry style deployment in mind.

It may need to be setup to parse your specific service instances, or you can automate setting up the environment instead.

The application uses redis as a quick session store, the application does not create or manage user accounts. 

### Settings

The settings are managed in the [config file](./config/config.js).  
Most settings can be configured through the environment.

The session store by default will use a file store on the host of the server.  A common directory (via NFS) can be used, 
but caution should be taken as this will store the user profile and might contain potentially sensitive information. 
