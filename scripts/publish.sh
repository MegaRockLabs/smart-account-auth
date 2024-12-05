cd packages/macros-proto && cargo publish && cd ../..
sleep 10
cd packages/schema && cargo publish && cd ../..
sleep 10
cd packages/common && cargo publish && cd ../..
sleep 10
cd packages/curves && cargo publish && cd ../..
sleep 10
cd packages/auth && cargo publish && cd ../..
sleep 10
cd packages/bundle && cargo publish && cd ../..
echo "All packages published"