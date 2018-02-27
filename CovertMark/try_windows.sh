for fn in `cat examples/local/runs.txt`; do
    python -u -m strategy.logistic_regression _ $1 $2 $3 _ $4 $5 $fn | tee examples/local/lr_${fn}_${3}_${5}.txt
    python -u -m strategy.sdg _ $1 $2 $3 _ $4 $5 $fn | tee examples/local/sdg_${fn}_${3}_${5}.txt
done
