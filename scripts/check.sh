# bundle crate
cargo features
cd packages/common && cargo package --allow-dirty && cd ../..
cd packages/crypto && cargo package --allow-dirty && cd ../..
cd packages/curves && cargo package --allow-dirty && cd ../..
cd packages/passkeys && cargo package --allow-dirty && cd ../..
cd packages/auth && cargo package --allow-dirty && cd ../..
cd packages/bundle && cargo package --allow-dirty && cd ../..
echo "All packages checked and ready to be published"