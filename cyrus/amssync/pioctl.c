/* Stub routine to get rid of the stupid NFS translator cruft */

pioctl(path, cmd, cmarg, follow)
char *path, *cmarg;
int cmd, follow;
{
    return lpioctl(path, cmd, cmarg, follow);
}
